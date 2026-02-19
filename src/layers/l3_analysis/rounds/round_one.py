"""
Round One Executor - Attack Surface Reconnaissance

First round of multi-round audit: fast scanning with Semgrep and Agent.
"""

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.engines.semgrep import SemgrepEngine
from src.layers.l3_analysis.models import Finding, FindingType, ScanResult, SeverityLevel
from src.layers.l3_analysis.rounds.models import (
    AnalysisDepth,
    AuditSession,
    ConfidenceLevel,
    CoverageStats,
    EngineStats,
    RoundResult,
    RoundStatus,
    VulnerabilityCandidate,
)
from src.layers.l3_analysis.strategy.models import (
    AuditPriorityLevel,
    AuditStrategy,
    AuditTarget,
)
from src.layers.l3_analysis.task.dispatcher import TaskDispatcher
from src.layers.l3_analysis.task.generator import TaskGenerator
from src.layers.l3_analysis.task.models import AgentTask, TaskResult


class RoundOneExecutor:
    """
    First round executor: Attack Surface Reconnaissance.

    This round performs:
    1. Semgrep fast scan on all code
    2. Agent entry point analysis on high-priority targets
    3. Initial vulnerability candidate collection
    """

    # Confidence mapping by severity
    SEVERITY_TO_CONFIDENCE = {
        SeverityLevel.CRITICAL: ConfidenceLevel.HIGH,
        SeverityLevel.HIGH: ConfidenceLevel.HIGH,
        SeverityLevel.MEDIUM: ConfidenceLevel.MEDIUM,
        SeverityLevel.LOW: ConfidenceLevel.LOW,
        SeverityLevel.INFO: ConfidenceLevel.LOW,
    }

    # Priority level to analysis depth
    PRIORITY_TO_DEPTH = {
        AuditPriorityLevel.CRITICAL: AnalysisDepth.DEEP,
        AuditPriorityLevel.HIGH: AnalysisDepth.STANDARD,
        AuditPriorityLevel.MEDIUM: AnalysisDepth.QUICK,
        AuditPriorityLevel.LOW: AnalysisDepth.QUICK,
    }

    def __init__(
        self,
        source_path: Path,
        semgrep_engine: SemgrepEngine | None = None,
        task_generator: TaskGenerator | None = None,
        task_dispatcher: TaskDispatcher | None = None,
        agent_executor: Any | None = None,
    ):
        """
        Initialize the round one executor.

        Args:
            source_path: Path to source code.
            semgrep_engine: Semgrep engine instance.
            task_generator: Task generator for Agent tasks.
            task_dispatcher: Task dispatcher for parallel execution.
            agent_executor: Async function to execute Agent tasks.
        """
        self.logger = get_logger(__name__)
        self.source_path = source_path
        self._semgrep_engine = semgrep_engine
        self._task_generator = task_generator or TaskGenerator()
        self._task_dispatcher = task_dispatcher or TaskDispatcher()
        self._agent_executor = agent_executor

    async def execute(
        self,
        strategy: AuditStrategy,
        previous_round: RoundResult | None = None,
    ) -> RoundResult:
        """
        Execute round one: Attack Surface Reconnaissance.

        Args:
            strategy: Audit strategy with targets.
            previous_round: Result from previous round (None for round one).

        Returns:
            Round result with initial vulnerability candidates.
        """
        self.logger.info("Starting Round 1: Attack Surface Reconnaissance")

        # Initialize round result
        round_result = RoundResult(
            round_number=1,
            status=RoundStatus.RUNNING,
            started_at=datetime.now(UTC),
        )

        # Initialize coverage stats
        coverage = CoverageStats(
            total_targets=strategy.total_targets,
            total_files=self._count_source_files(),
        )

        try:
            # Phase 1: Semgrep Fast Scan
            semgrep_stats = await self._run_semgrep_scan(strategy, round_result, coverage)

            # Phase 2: Agent Entry Point Analysis (high priority targets only)
            agent_stats = await self._run_agent_analysis(strategy, round_result, coverage)

            # Update engine stats
            round_result.engine_stats["semgrep"] = semgrep_stats
            round_result.engine_stats["agent"] = agent_stats

            # Phase 3: Identify candidates for next round
            self._identify_next_round_candidates(round_result)

            # Update coverage
            round_result.coverage = coverage

            # Mark completed
            round_result.mark_completed()

            self.logger.info(
                f"Round 1 completed: {round_result.total_candidates} candidates, "
                f"{len(round_result.next_round_candidates)} for deep analysis"
            )

        except Exception as e:
            self.logger.error(f"Round 1 failed: {e}")
            round_result.mark_failed(str(e))

        return round_result

    async def _run_semgrep_scan(
        self,
        strategy: AuditStrategy,
        round_result: RoundResult,
        coverage: CoverageStats,
    ) -> EngineStats:
        """Run Semgrep scan on all source files."""
        self.logger.info("Phase 1: Semgrep Fast Scan")

        stats = EngineStats(
            engine="semgrep",
            enabled=True,
            start_time=datetime.now(UTC),
        )

        try:
            # Get or create Semgrep engine
            if not self._semgrep_engine:
                self._semgrep_engine = SemgrepEngine()

            # Run scan
            scan_result = await self._semgrep_engine.scan(
                source_path=self.source_path,
                rule_sets=["security"],  # Use security rules
            )

            stats.executed = True

            # Process findings
            for finding in scan_result.findings:
                candidate = self._create_candidate(
                    finding=finding,
                    round_number=1,
                    analysis_depth=AnalysisDepth.QUICK,
                )
                round_result.add_candidate(candidate)

            # Update stats
            stats.findings_count = len(scan_result.findings)
            stats.candidates_count = len(scan_result.findings)
            stats.files_scanned = coverage.total_files
            stats.duration_seconds = scan_result.duration_seconds

            # Update coverage
            coverage.scanned_files = coverage.total_files
            coverage.scanned_lines = scan_result.metadata.get("total_lines", 0)

            self.logger.info(
                f"Semgrep completed: {stats.findings_count} findings"
            )

        except Exception as e:
            self.logger.error(f"Semgrep scan failed: {e}")
            stats.add_error(str(e))

        stats.end_time = datetime.now(UTC)
        if stats.start_time:
            stats.duration_seconds = (
                stats.end_time - stats.start_time
            ).total_seconds()

        return stats

    async def _run_agent_analysis(
        self,
        strategy: AuditStrategy,
        round_result: RoundResult,
        coverage: CoverageStats,
    ) -> EngineStats:
        """Run Agent analysis on high-priority targets."""
        self.logger.info("Phase 2: Agent Entry Point Analysis")

        stats = EngineStats(
            engine="agent",
            enabled=self._agent_executor is not None,
            start_time=datetime.now(UTC),
        )

        if not self._agent_executor:
            self.logger.info("Agent executor not provided, skipping Agent analysis")
            stats.add_warning("Agent executor not provided")
            stats.end_time = datetime.now(UTC)
            return stats

        try:
            # Get high-priority targets
            critical_targets = strategy.get_critical_targets()
            high_targets = strategy.get_high_targets()

            targets_to_analyze = critical_targets + high_targets

            if not targets_to_analyze:
                self.logger.info("No high-priority targets for Agent analysis")
                stats.add_warning("No high-priority targets")
                stats.end_time = datetime.now(UTC)
                return stats

            # Generate tasks
            tasks = self._task_generator.generate_tasks(targets_to_analyze)

            if not tasks:
                self.logger.info("No tasks generated for Agent")
                stats.end_time = datetime.now(UTC)
                return stats

            stats.executed = True
            stats.targets_analyzed = len(targets_to_analyze)

            # Add tasks to dispatcher
            self._task_dispatcher.reset()
            self._task_dispatcher.add_tasks(tasks)

            # Execute tasks
            completed_tasks = await self._task_dispatcher.execute_all(
                executor=self._agent_executor
            )

            # Process results
            for task in completed_tasks:
                if task.result and task.result.success:
                    for finding_raw in task.result.findings_raw:
                        finding = self._raw_to_finding(finding_raw, "agent")
                        candidate = self._create_candidate(
                            finding=finding,
                            round_number=1,
                            analysis_depth=AnalysisDepth.STANDARD,
                            needs_deep_analysis=True,  # Agent findings need verification
                        )
                        round_result.add_candidate(candidate)

            # Update stats
            stats.findings_count = sum(
                len(t.result.findings_raw) for t in completed_tasks
                if t.result
            )
            stats.candidates_count = stats.findings_count
            stats.tokens_used = self._task_dispatcher.get_statistics().get("total_tokens", 0)

            # Update coverage
            coverage.analyzed_targets = len(targets_to_analyze)
            coverage.critical_targets_analyzed = len(critical_targets)
            coverage.high_targets_analyzed = len(high_targets)

            self.logger.info(
                f"Agent completed: {len(completed_tasks)} tasks, {stats.findings_count} findings"
            )

        except Exception as e:
            self.logger.error(f"Agent analysis failed: {e}")
            stats.add_error(str(e))

        stats.end_time = datetime.now(UTC)
        if stats.start_time:
            stats.duration_seconds = (
                stats.end_time - stats.start_time
            ).total_seconds()

        return stats

    def _create_candidate(
        self,
        finding: Finding,
        round_number: int,
        analysis_depth: AnalysisDepth,
        needs_deep_analysis: bool = False,
    ) -> VulnerabilityCandidate:
        """Create a vulnerability candidate from a finding."""
        confidence = self.SEVERITY_TO_CONFIDENCE.get(
            finding.severity,
            ConfidenceLevel.MEDIUM
        )

        # Adjust confidence based on source
        if finding.source == "agent":
            # Agent findings have higher confidence
            if confidence == ConfidenceLevel.MEDIUM:
                confidence = ConfidenceLevel.HIGH

        return VulnerabilityCandidate(
            id=f"candidate-{uuid.uuid4().hex[:8]}",
            finding=finding,
            confidence=confidence,
            analysis_depth=analysis_depth,
            discovered_in_round=round_number,
            analyzed_in_rounds=[round_number],
            needs_deep_analysis=needs_deep_analysis,
            related_targets=[],
        )

    def _raw_to_finding(
        self,
        raw: dict[str, Any],
        source: str,
    ) -> Finding:
        """Convert raw finding dict to Finding model."""
        from src.layers.l3_analysis.models import CodeLocation

        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
        }

        severity_str = raw.get("severity", "medium").lower()
        severity = severity_map.get(severity_str, SeverityLevel.MEDIUM)

        return Finding(
            id=f"finding-{uuid.uuid4().hex[:8]}",
            rule_id=raw.get("rule_id"),
            type=FindingType.VULNERABILITY,
            severity=severity,
            confidence=raw.get("confidence", 0.8),
            title=raw.get("title", "Unknown Vulnerability"),
            description=raw.get("description", ""),
            location=CodeLocation(
                file=raw.get("file", "unknown"),
                line=raw.get("line", 1),
                function=raw.get("function"),
            ),
            source=source,
            cwe=raw.get("cwe"),
            tags=raw.get("tags", []),
        )

    def _identify_next_round_candidates(
        self,
        round_result: RoundResult,
    ) -> None:
        """Identify candidates that need analysis in round 2."""
        for candidate in round_result.candidates:
            # High/Medium confidence candidates need deep analysis
            if candidate.confidence in (ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM):
                candidate.needs_deep_analysis = True
                round_result.next_round_candidates.append(candidate.id)

            # Critical/High severity always needs verification
            if candidate.finding.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
                if candidate.id not in round_result.next_round_candidates:
                    round_result.next_round_candidates.append(candidate.id)

    def _count_source_files(self) -> int:
        """Count source code files in the project."""
        extensions = {".py", ".java", ".go", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".cs"}
        count = 0

        for ext in extensions:
            count += len(list(self.source_path.rglob(f"*{ext}")))

        return count
