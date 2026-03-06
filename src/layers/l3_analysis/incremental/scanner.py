"""
Incremental Scanner - Coordinate incremental scanning workflow.

Orchestrates change detection, impact analysis, and selective scanning
to achieve fast incremental analysis with 70%+ speedup.
"""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.incremental.baseline_manager import (
    BaselineManager,
)
from src.layers.l3_analysis.incremental.change_detector import (
    ChangeDetector,
)
from src.layers.l3_analysis.incremental.dependency_graph import DependencyGraph
from src.layers.l3_analysis.incremental.impact_analyzer import (
    ImpactAnalyzer,
)

logger = get_logger(__name__)


@dataclass
class IncrementalScanConfig:
    """Configuration for incremental scanning."""

    # Change detection
    base_ref: str = "HEAD~1"  # Base commit/branch for comparison
    head_ref: str = "HEAD"  # Head commit/branch
    include_untracked: bool = False  # Include untracked files

    # Impact analysis
    min_impact_score: float = 0.15  # Minimum score to include file
    max_dependency_depth: int = 4  # Maximum dependency traversal depth
    prioritize_entry_points: bool = True  # Prioritize entry point files

    # Scanning
    parallel_scans: int = 3  # Number of parallel file scans
    scan_timeout_seconds: int = 300  # Timeout per file

    # Baseline
    baseline_enabled: bool = True  # Enable baseline comparison
    baseline_path: str = ".deepvuln/baseline.json"  # Baseline storage path
    update_baseline: bool = True  # Update baseline after scan

    # Performance
    enable_cache: bool = True  # Enable result caching
    cache_path: str = ".deepvuln/cache"  # Cache storage path

    # Filtering
    extensions: list[str] | None = None  # File extensions to scan
    exclude_patterns: list[str] | None = None  # Patterns to exclude

    # Reporting
    report_new_only: bool = False  # Only report new vulnerabilities
    include_fixed: bool = True  # Include fixed vulns in report


@dataclass
class IncrementalScanResult:
    """Result of an incremental scan."""

    # Scan info
    project_path: str = ""
    base_ref: str = ""
    head_ref: str = ""
    scan_time: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Change detection
    files_changed: int = 0
    files_added: int = 0
    files_modified: int = 0
    files_deleted: int = 0

    # Impact analysis
    files_affected: int = 0
    coverage_ratio: float = 0.0
    impact_levels: dict[str, str] = field(default_factory=dict)  # file -> level

    # Scanning
    files_scanned: int = 0
    files_skipped: int = 0
    files_cached: int = 0

    # Findings
    total_findings: int = 0
    new_findings: int = 0
    persistent_findings: int = 0
    fixed_findings: int = 0

    # Detailed results
    findings: list[dict[str, Any]] = field(default_factory=list)
    new_vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    fixed_vulnerabilities: list[dict[str, Any]] = field(default_factory=list)

    # Performance
    duration_seconds: float = 0.0
    change_detection_ms: float = 0.0
    impact_analysis_ms: float = 0.0
    scan_execution_ms: float = 0.0
    speedup_factor: float = 1.0

    # Status
    success: bool = True
    error_message: str | None = None

    def to_summary(self) -> str:
        """Generate a summary of the scan result."""
        lines = [
            "Incremental Scan Results",
            f"{'=' * 40}",
            f"Project: {self.project_path}",
            f"Base: {self.base_ref} -> Head: {self.head_ref}",
            "",
            "Changes Detected:",
            f"  Files changed: {self.files_changed}",
            f"  Added: {self.files_added}, Modified: {self.files_modified}, Deleted: {self.files_deleted}",
            "",
            "Impact Analysis:",
            f"  Files affected: {self.files_affected}",
            f"  Coverage: {self.coverage_ratio:.1%}",
            "",
            "Scan Results:",
            f"  Files scanned: {self.files_scanned}",
            f"  Files skipped: {self.files_skipped}",
            f"  Cache hits: {self.files_cached}",
            "",
            "Findings:",
            f"  Total: {self.total_findings}",
            f"  New: {self.new_findings}",
            f"  Persistent: {self.persistent_findings}",
            f"  Fixed: {self.fixed_findings}",
            "",
            "Performance:",
            f"  Duration: {self.duration_seconds:.2f}s",
            f"  Speedup: {self.speedup_factor:.1f}x",
        ]
        return "\n".join(lines)


class IncrementalScanner:
    """
    Coordinates incremental scanning workflow.

    Integrates change detection, impact analysis, baseline comparison,
    and selective scanning for fast incremental vulnerability detection.
    """

    def __init__(
        self,
        project_path: str | Path,
        config: IncrementalScanConfig | None = None,
        scan_callback: Callable[[list[str]], list[dict[str, Any]]] | None = None,
    ):
        """
        Initialize the incremental scanner.

        Args:
            project_path: Path to the project to scan.
            config: Configuration for incremental scanning.
            scan_callback: Optional callback for custom scanning logic.
        """
        self.project_path = Path(project_path).resolve()
        self.config = config or IncrementalScanConfig()
        self.scan_callback = scan_callback

        # Initialize components
        self.change_detector = ChangeDetector(
            repo_path=self.project_path,
            ignore_patterns=self.config.exclude_patterns,
        )

        self.dependency_graph = DependencyGraph(
            project_path=self.project_path,
            exclude_patterns=self.config.exclude_patterns,
            max_depth=self.config.max_dependency_depth,
        )

        self.impact_analyzer: ImpactAnalyzer | None = None
        self.baseline_manager: BaselineManager | None = None

        # State
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the incremental scanner components."""
        if self._initialized:
            return

        logger.info("Initializing incremental scanner...")

        # Build dependency graph
        await self.dependency_graph.build()

        # Initialize impact analyzer
        self.impact_analyzer = ImpactAnalyzer(
            dependency_graph=self.dependency_graph,
            min_impact_score=self.config.min_impact_score,
            max_depth=self.config.max_dependency_depth,
            prioritize_entry_points=self.config.prioritize_entry_points,
        )

        # Initialize baseline manager
        if self.config.baseline_enabled:
            project_hash = self._compute_project_hash()
            self.baseline_manager = BaselineManager(
                baseline_path=self.project_path / self.config.baseline_path,
                project_hash=project_hash,
                auto_save=True,
            )
            await self.baseline_manager.load()

        self._initialized = True
        logger.info("Incremental scanner initialized")

    def _compute_project_hash(self) -> str:
        """Compute a hash to identify this project."""
        import hashlib
        content = f"{self.project_path.name}:{self.project_path.stat().st_size}"
        return hashlib.md5(content.encode()).hexdigest()[:8]

    async def scan(self) -> IncrementalScanResult:
        """
        Execute an incremental scan.

        Returns:
            IncrementalScanResult with scan results.
        """
        start_time = datetime.now(UTC)

        result = IncrementalScanResult(
            project_path=str(self.project_path),
            base_ref=self.config.base_ref,
            head_ref=self.config.head_ref,
        )

        try:
            # Ensure initialized
            if not self._initialized:
                await self.initialize()

            # Step 1: Detect changes
            logger.info(f"Detecting changes: {self.config.base_ref}..{self.config.head_ref}")
            change_start = datetime.now(UTC)

            diff_result = await self.change_detector.detect_changes(
                base_ref=self.config.base_ref,
                head_ref=self.config.head_ref,
                include_untracked=self.config.include_untracked,
            )

            result.change_detection_ms = (datetime.now(UTC) - change_start).total_seconds() * 1000
            result.files_changed = diff_result.total_files_changed
            result.files_added = diff_result.files_added
            result.files_modified = diff_result.files_modified
            result.files_deleted = diff_result.files_deleted

            logger.info(
                f"Changes detected: {result.files_changed} files "
                f"({result.files_added} added, {result.files_modified} modified, {result.files_deleted} deleted)"
            )

            # If no changes, return early
            if not diff_result.has_changes:
                logger.info("No changes detected, skipping scan")
                result.duration_seconds = (datetime.now(UTC) - start_time).total_seconds()
                return result

            # Step 2: Analyze impact
            logger.info("Analyzing impact...")
            impact_start = datetime.now(UTC)

            impact_result = self.impact_analyzer.analyze(diff_result)

            result.impact_analysis_ms = (datetime.now(UTC) - impact_start).total_seconds() * 1000
            result.files_affected = len(impact_result.files_to_scan)
            result.coverage_ratio = impact_result.coverage_ratio
            result.impact_levels = {
                f: (level.value if (level := impact_result.get_impact_level(f)) else "minimal")
                for f in impact_result.files_to_scan
            }

            logger.info(
                f"Impact analysis complete: {result.files_affected} files affected "
                f"({result.coverage_ratio:.1%} coverage)"
            )

            # Step 3: Get files to scan
            files_to_scan = self.change_detector.get_scan_eligible_files(
                diff_result,
                extensions=self.config.extensions,
            )

            # Add affected files from impact analysis
            files_to_scan.extend([
                f for f in impact_result.files_to_scan
                if f not in files_to_scan and (self.project_path / f).exists()
            ])

            # Deduplicate
            files_to_scan = list(set(files_to_scan))
            result.files_scanned = len(files_to_scan)
            result.files_skipped = len(self.dependency_graph.nodes) - result.files_scanned

            # Step 4: Execute scan
            logger.info(f"Scanning {result.files_scanned} files...")
            scan_start = datetime.now(UTC)

            findings = await self._execute_scan(files_to_scan)

            result.scan_execution_ms = (datetime.now(UTC) - scan_start).total_seconds() * 1000
            result.total_findings = len(findings)
            result.findings = findings

            # Step 5: Compare with baseline
            if self.baseline_manager and self.config.baseline_enabled:
                logger.info("Comparing with baseline...")

                baseline_diff = self.baseline_manager.compare(
                    findings,
                    current_commit=self.config.head_ref,
                )

                result.new_findings = baseline_diff.new_count
                result.persistent_findings = baseline_diff.persistent_count
                result.fixed_findings = baseline_diff.fixed_count
                result.new_vulnerabilities = baseline_diff.new_vulnerabilities
                result.fixed_vulnerabilities = baseline_diff.fixed_vulnerabilities

                # Update baseline if configured
                if self.config.update_baseline:
                    self.baseline_manager.update_baseline(
                        findings,
                        commit_hash=self.config.head_ref,
                    )
                    await self.baseline_manager.save()
            else:
                # Without baseline, all findings are "new"
                result.new_findings = result.total_findings
                result.new_vulnerabilities = [
                    {"finding": f, "status": "new"}
                    for f in findings
                ]

            # Calculate speedup
            total_files = len(self.dependency_graph.nodes)
            if result.files_scanned > 0 and total_files > 0:
                result.speedup_factor = round(total_files / result.files_scanned, 2)

            result.duration_seconds = (datetime.now(UTC) - start_time).total_seconds()
            result.success = True

            logger.info(
                f"Incremental scan complete: {result.total_findings} findings "
                f"({result.new_findings} new, {result.fixed_findings} fixed) "
                f"in {result.duration_seconds:.2f}s ({result.speedup_factor}x speedup)"
            )

        except Exception as e:
            logger.error(f"Incremental scan failed: {e}")
            result.success = False
            result.error_message = str(e)
            result.duration_seconds = (datetime.now(UTC) - start_time).total_seconds()

        return result

    async def _execute_scan(
        self,
        files: list[str],
    ) -> list[dict[str, Any]]:
        """
        Execute scanning on the specified files.

        Args:
            files: List of file paths to scan.

        Returns:
            List of vulnerability findings.
        """
        if self.scan_callback:
            # Use custom scan callback
            return await asyncio.to_thread(self.scan_callback, files)

        # Default: return placeholder findings
        # In production, this would call the actual scanner engines
        findings: list[dict[str, Any]] = []

        # Simulate scanning with parallel batches
        batch_size = self.config.parallel_scans
        for i in range(0, len(files), batch_size):
            batch = files[i:i + batch_size]

            # Process batch in parallel
            tasks = [self._scan_single_file(f) for f in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for file_path, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    logger.debug(f"Failed to scan {file_path}: {result}")
                elif isinstance(result, list):
                    findings.extend(result)

        return findings

    async def _scan_single_file(
        self,
        file_path: str,
    ) -> list[dict[str, Any]]:
        """
        Scan a single file for vulnerabilities.

        This is a placeholder that would be replaced with actual
        scanner integration in production.

        Args:
            file_path: Path to the file to scan.

        Returns:
            List of findings for this file.
        """
        # Placeholder: In production, this would call Semgrep/CodeQL/Agent
        await asyncio.sleep(0.1)  # Simulate scan time
        return []

    async def full_scan(self) -> IncrementalScanResult:
        """
        Execute a full scan (non-incremental).

        Returns:
            IncrementalScanResult with all files scanned.
        """
        if not self._initialized:
            await self.initialize()

        start_time = datetime.now(UTC)

        result = IncrementalScanResult(
            project_path=str(self.project_path),
            base_ref="FULL",
            head_ref="FULL",
        )

        try:
            # Get all source files
            all_files = list(self.dependency_graph.nodes.keys())
            result.files_scanned = len(all_files)

            # Execute scan
            logger.info(f"Executing full scan on {result.files_scanned} files...")
            scan_start = datetime.now(UTC)

            findings = await self._execute_scan(all_files)

            result.scan_execution_ms = (datetime.now(UTC) - scan_start).total_seconds() * 1000
            result.total_findings = len(findings)
            result.findings = findings
            result.new_findings = result.total_findings

            # Update baseline
            if self.baseline_manager and self.config.update_baseline:
                self.baseline_manager.update_baseline(findings)
                await self.baseline_manager.save()

            result.duration_seconds = (datetime.now(UTC) - start_time).total_seconds()
            result.success = True
            result.speedup_factor = 1.0
            result.coverage_ratio = 1.0

        except Exception as e:
            logger.error(f"Full scan failed: {e}")
            result.success = False
            result.error_message = str(e)
            result.duration_seconds = (datetime.now(UTC) - start_time).total_seconds()

        return result

    def get_scan_plan(
        self,
        base_ref: str | None = None,
        head_ref: str | None = None,
    ) -> dict[str, Any]:
        """
        Get a scan plan without executing the scan.

        Args:
            base_ref: Base commit/branch.
            head_ref: Head commit/branch.

        Returns:
            Dictionary with scan plan details.
        """
        base_ref = base_ref or self.config.base_ref
        head_ref = head_ref or self.config.head_ref

        return {
            "project_path": str(self.project_path),
            "base_ref": base_ref,
            "head_ref": head_ref,
            "dependency_graph_stats": self.dependency_graph.get_statistics(),
            "baseline_stats": self.baseline_manager.get_statistics() if self.baseline_manager else None,
            "config": {
                "min_impact_score": self.config.min_impact_score,
                "max_dependency_depth": self.config.max_dependency_depth,
                "parallel_scans": self.config.parallel_scans,
                "baseline_enabled": self.config.baseline_enabled,
            },
        }

    async def estimate_speedup(
        self,
        base_ref: str | None = None,
        head_ref: str | None = None,
    ) -> dict[str, Any]:
        """
        Estimate the speedup from incremental scanning.

        Args:
            base_ref: Base commit/branch.
            head_ref: Head commit/branch.

        Returns:
            Dictionary with speedup estimates.
        """
        base_ref = base_ref or self.config.base_ref
        head_ref = head_ref or self.config.head_ref

        # Detect changes
        diff_result = await self.change_detector.detect_changes(
            base_ref=base_ref,
            head_ref=head_ref,
        )

        # Analyze impact
        if not self._initialized:
            await self.initialize()

        impact_result = self.impact_analyzer.analyze(diff_result)

        # Estimate speedup
        total_files = len(self.dependency_graph.nodes)
        files_to_scan = len(impact_result.files_to_scan)

        return {
            "total_project_files": total_files,
            "changed_files": diff_result.total_files_changed,
            "files_to_scan": files_to_scan,
            "files_skipped": total_files - files_to_scan,
            "estimated_speedup": round(total_files / files_to_scan, 2) if files_to_scan > 0 else float("inf"),
            "time_saved_percent": round((1 - files_to_scan / total_files) * 100, 1) if total_files > 0 else 0,
        }
