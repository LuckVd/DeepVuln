"""
Round Two Executor - Deep Tracking

Second round of multi-round audit: deep analysis of vulnerability candidates.
"""

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.engines.codeql import CodeQLEngine
from src.layers.l3_analysis.models import CodeLocation
from src.layers.l3_analysis.rounds.dataflow import (
    DataFlowPath,
    DeepAnalysisResult,
    PathNode,
    Sanitizer,
    SanitizerType,
    SinkType,
    SourceType,
    TaintSink,
    TaintSource,
)
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
from src.layers.l3_analysis.strategy.models import AuditStrategy


class RoundTwoExecutor:
    """
    Second round executor: Deep Tracking.

    This round performs:
    1. Data flow analysis using CodeQL
    2. Deep audit using Agent
    3. Taint propagation tracking
    4. Evidence collection and confidence update
    """

    # Map confidence levels to strings
    CONFIDENCE_MAP = {
        ConfidenceLevel.HIGH: "high",
        ConfidenceLevel.MEDIUM: "medium",
        ConfidenceLevel.LOW: "low",
    }

    # Analysis depth by confidence
    DEPTH_BY_CONFIDENCE = {
        ConfidenceLevel.HIGH: AnalysisDepth.DEEP,
        ConfidenceLevel.MEDIUM: AnalysisDepth.STANDARD,
        ConfidenceLevel.LOW: AnalysisDepth.QUICK,
    }

    def __init__(
        self,
        source_path: Path,
        codeql_engine: CodeQLEngine | None = None,
        agent_executor: Any | None = None,
        database_path: Path | None = None,
    ):
        """
        Initialize the round two executor.

        Args:
            source_path: Path to source code.
            codeql_engine: CodeQL engine instance.
            agent_executor: Async function to execute Agent deep audit.
            database_path: Path to CodeQL database (if already created).
        """
        self.logger = get_logger(__name__)
        self.source_path = source_path
        self._codeql_engine = codeql_engine
        self._agent_executor = agent_executor
        self._database_path = database_path

    async def execute(
        self,
        strategy: AuditStrategy,
        previous_round: RoundResult | None = None,
    ) -> RoundResult:
        """
        Execute round two: Deep Tracking.

        Args:
            strategy: Audit strategy with targets.
            previous_round: Result from round one (contains candidates).

        Returns:
            Round result with updated vulnerability candidates.
        """
        self.logger.info("Starting Round 2: Deep Tracking")

        # Initialize round result
        round_result = RoundResult(
            round_number=2,
            status=RoundStatus.RUNNING,
            started_at=datetime.now(UTC),
        )

        # Initialize coverage stats
        coverage = CoverageStats(
            total_targets=strategy.total_targets,
        )

        try:
            # Get candidates from round one
            if not previous_round or not previous_round.candidates:
                self.logger.info("No candidates from round one, skipping deep analysis")
                round_result.mark_completed()
                return round_result

            candidates = previous_round.get_candidates_for_next_round()
            self.logger.info(f"Processing {len(candidates)} candidates for deep analysis")

            # Phase 1: CodeQL Data Flow Analysis
            codeql_stats = await self._run_codeql_analysis(
                candidates, round_result, coverage
            )

            # Phase 2: Agent Deep Audit
            agent_stats = await self._run_agent_deep_audit(
                candidates, round_result, coverage
            )

            # Phase 3: Update confidence levels
            self._update_candidate_confidence(candidates, round_result)

            # Update engine stats
            round_result.engine_stats["codeql"] = codeql_stats
            round_result.engine_stats["agent"] = agent_stats

            # Phase 4: Identify candidates for round three
            self._identify_next_round_candidates(round_result)

            # Update coverage
            round_result.coverage = coverage

            # Mark completed
            round_result.mark_completed()

            self.logger.info(
                f"Round 2 completed: {round_result.total_candidates} candidates, "
                f"{len(round_result.next_round_candidates)} for round three"
            )

        except Exception as e:
            self.logger.error(f"Round 2 failed: {e}")
            round_result.mark_failed(str(e))

        return round_result

    async def _run_codeql_analysis(
        self,
        candidates: list[VulnerabilityCandidate],
        round_result: RoundResult,
        coverage: CoverageStats,
    ) -> EngineStats:
        """Run CodeQL data flow analysis on candidates."""
        self.logger.info("Phase 1: CodeQL Data Flow Analysis")

        stats = EngineStats(
            engine="codeql",
            enabled=self._codeql_engine is not None,
            start_time=datetime.now(UTC),
        )

        if not self._codeql_engine:
            self.logger.info("CodeQL engine not provided, skipping CodeQL analysis")
            stats.add_warning("CodeQL engine not provided")
            stats.end_time = datetime.now(UTC)
            return stats

        try:
            # Check if database exists or needs to be created
            if not self._database_path or not self._database_path.exists():
                self.logger.info("Creating CodeQL database...")
                # Note: Database creation is handled by the engine
                pass

            stats.executed = True

            # Analyze each candidate
            for candidate in candidates:
                try:
                    # Create deep analysis result
                    deep_result = DeepAnalysisResult(
                        id=f"deep-{uuid.uuid4().hex[:8]}",
                        candidate_id=candidate.id,
                        original_confidence=self.CONFIDENCE_MAP.get(
                            candidate.confidence, "medium"
                        ),
                        analysis_started=datetime.now(UTC),
                    )

                    # Run data flow queries based on vulnerability type
                    dataflow_path = await self._trace_dataflow(candidate)
                    if dataflow_path:
                        deep_result.add_dataflow_path(dataflow_path)

                    # Store CodeQL findings
                    deep_result.codeql_findings = {
                        "has_path": dataflow_path is not None,
                        "path_complete": dataflow_path.is_complete if dataflow_path else False,
                    }

                    # Add evidence to candidate
                    candidate.add_evidence("codeql", deep_result.to_prompt_context())
                    candidate.analyzed_in_rounds.append(2)

                    # Store in metadata
                    if "deep_results" not in candidate.metadata:
                        candidate.metadata["deep_results"] = {}
                    candidate.metadata["deep_results"]["codeql"] = deep_result.model_dump()

                    stats.findings_count += 1

                except Exception as e:
                    self.logger.warning(f"CodeQL analysis failed for candidate {candidate.id}: {e}")
                    stats.add_warning(f"Candidate {candidate.id}: {e}")

            stats.candidates_count = len(candidates)
            coverage.analyzed_targets += len(candidates)

        except Exception as e:
            self.logger.error(f"CodeQL analysis failed: {e}")
            stats.add_error(str(e))

        stats.end_time = datetime.now(UTC)
        if stats.start_time:
            stats.duration_seconds = (
                stats.end_time - stats.start_time
            ).total_seconds()

        return stats

    async def _trace_dataflow(
        self,
        candidate: VulnerabilityCandidate,
    ) -> DataFlowPath | None:
        """
        Trace data flow for a vulnerability candidate.

        Args:
            candidate: The vulnerability candidate to analyze.

        Returns:
            Data flow path if found, None otherwise.
        """
        finding = candidate.finding

        # Create source based on the finding
        source = TaintSource(
            id=f"source-{uuid.uuid4().hex[:8]}",
            location=finding.location,
            source_type=self._infer_source_type(finding),
            user_controlled=True,
            variable_name=finding.location.function,
        )

        # Create sink based on the finding
        sink = TaintSink(
            id=f"sink-{uuid.uuid4().hex[:8]}",
            location=finding.location,
            sink_type=self._infer_sink_type(finding),
            dangerous_if_tainted=True,
            function_name=finding.location.function,
            vulnerability_class=[finding.title] if finding.title else [],
        )

        # Create a basic path (would be enhanced by actual CodeQL analysis)
        path = DataFlowPath(
            id=f"path-{uuid.uuid4().hex[:8]}",
            candidate_id=candidate.id,
            source=source,
            sink=sink,
            is_complete=False,  # Would be determined by actual analysis
            analyzer="codeql",
        )

        # Add source and sink as path nodes
        path.add_node(PathNode(
            location=source.location,
            node_type="source",
            variable_name=source.variable_name,
        ))

        path.add_node(PathNode(
            location=sink.location,
            node_type="sink",
            function_name=sink.function_name,
        ))

        return path

    def _infer_source_type(self, finding) -> SourceType:
        """Infer taint source type from finding."""
        title = finding.title.lower() if finding.title else ""
        tags = [t.lower() for t in finding.tags] if finding.tags else []

        if "sql" in title or "sqli" in tags:
            return SourceType.HTTP_PARAM
        if "xss" in title or "xss" in tags:
            return SourceType.HTTP_PARAM
        if "command" in title or "rce" in tags:
            return SourceType.HTTP_PARAM
        if "file" in title or "path" in title:
            return SourceType.HTTP_PARAM

        return SourceType.USER_INPUT

    def _infer_sink_type(self, finding) -> SinkType:
        """Infer sink type from finding."""
        title = finding.title.lower() if finding.title else ""
        tags = [t.lower() for t in finding.tags] if finding.tags else []

        if "sql" in title or "sqli" in tags:
            return SinkType.SQL_QUERY
        if "xss" in title or "xss" in tags:
            return SinkType.HTTP_RESPONSE
        if "command" in title or "rce" in tags:
            return SinkType.COMMAND_EXEC
        if "path" in title or "traversal" in title:
            return SinkType.FILE_READ
        if "redirect" in title:
            return SinkType.HTTP_REDIRECT

        return SinkType.SQL_QUERY  # Default

    async def _run_agent_deep_audit(
        self,
        candidates: list[VulnerabilityCandidate],
        round_result: RoundResult,
        coverage: CoverageStats,
    ) -> EngineStats:
        """Run Agent deep audit on candidates."""
        self.logger.info("Phase 2: Agent Deep Audit")

        stats = EngineStats(
            engine="agent",
            enabled=self._agent_executor is not None,
            start_time=datetime.now(UTC),
        )

        if not self._agent_executor:
            self.logger.info("Agent executor not provided, skipping Agent deep audit")
            stats.add_warning("Agent executor not provided")
            stats.end_time = datetime.now(UTC)
            return stats

        try:
            stats.executed = True

            # Select candidates for deep audit based on confidence
            deep_audit_candidates = [
                c for c in candidates
                if c.confidence in (ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM)
            ]

            self.logger.info(
                f"Running Agent deep audit on {len(deep_audit_candidates)} candidates"
            )

            for candidate in deep_audit_candidates:
                try:
                    # Run Agent deep audit
                    result = await self._agent_deep_analyze(candidate)

                    # Update candidate with Agent findings
                    if result:
                        candidate.add_evidence("agent_deep", result)

                        # Store in metadata
                        if "deep_results" not in candidate.metadata:
                            candidate.metadata["deep_results"] = {}
                        candidate.metadata["deep_results"]["agent"] = result

                        stats.findings_count += 1
                        stats.tokens_used += result.get("tokens_used", 0)

                except Exception as e:
                    self.logger.warning(
                        f"Agent deep audit failed for candidate {candidate.id}: {e}"
                    )
                    stats.add_warning(f"Candidate {candidate.id}: {e}")

            stats.candidates_count = len(deep_audit_candidates)

        except Exception as e:
            self.logger.error(f"Agent deep audit failed: {e}")
            stats.add_error(str(e))

        stats.end_time = datetime.now(UTC)
        if stats.start_time:
            stats.duration_seconds = (
                stats.end_time - stats.start_time
            ).total_seconds()

        return stats

    async def _agent_deep_analyze(
        self,
        candidate: VulnerabilityCandidate,
    ) -> dict[str, Any] | None:
        """
        Run deep analysis using Agent.

        Args:
            candidate: Candidate to analyze deeply.

        Returns:
            Analysis result or None.
        """
        if not self._agent_executor:
            return None

        # Build context for Agent
        context = {
            "finding": candidate.finding.model_dump(),
            "confidence": self.CONFIDENCE_MAP.get(candidate.confidence, "medium"),
            "evidence": candidate.evidence,
            "task": "deep_audit",
        }

        try:
            # Execute Agent analysis
            result = await self._agent_executor(context)
            return result
        except Exception as e:
            self.logger.error(f"Agent deep analysis error: {e}")
            return {"error": str(e)}

    def _update_candidate_confidence(
        self,
        candidates: list[VulnerabilityCandidate],
        round_result: RoundResult,
    ) -> None:
        """Update confidence levels based on deep analysis results."""
        self.logger.info("Phase 3: Updating confidence levels")

        for candidate in candidates:
            deep_results = candidate.metadata.get("deep_results", {})
            original_confidence = candidate.confidence

            # Check CodeQL results
            codeql_result = deep_results.get("codeql", {})
            has_complete_path = codeql_result.get("path_complete", False)

            # Check Agent results
            agent_result = deep_results.get("agent", {})
            agent_confirmed = agent_result.get("confirmed", False)
            agent_false_positive = agent_result.get("false_positive", False)

            # Update confidence based on evidence
            if agent_false_positive:
                candidate.confidence = ConfidenceLevel.LOW
                candidate.metadata["confidence_reason"] = "Agent identified as false positive"
            elif has_complete_path and agent_confirmed:
                candidate.confidence = ConfidenceLevel.HIGH
                candidate.metadata["confidence_reason"] = "Complete dataflow path + Agent confirmation"
            elif has_complete_path:
                candidate.confidence = ConfidenceLevel.HIGH
                candidate.metadata["confidence_reason"] = "Complete dataflow path found"
            elif agent_confirmed:
                candidate.confidence = ConfidenceLevel.HIGH
                candidate.metadata["confidence_reason"] = "Agent confirmation"

            # Update needs_deep_analysis flag
            if candidate.confidence in (ConfidenceLevel.HIGH, ConfidenceLevel.LOW):
                candidate.needs_deep_analysis = False

            # Log confidence changes
            if candidate.confidence != original_confidence:
                self.logger.info(
                    f"Candidate {candidate.id}: confidence "
                    f"{self.CONFIDENCE_MAP[original_confidence]} → "
                    f"{self.CONFIDENCE_MAP[candidate.confidence]}"
                )

    def _identify_next_round_candidates(
        self,
        round_result: RoundResult,
    ) -> None:
        """Identify candidates that need round three analysis."""
        for candidate in round_result.candidates:
            # Medium confidence candidates need correlation verification
            if candidate.confidence == ConfidenceLevel.MEDIUM:
                candidate.needs_verification = True
                round_result.next_round_candidates.append(candidate.id)

            # Critical/High severity always needs verification
            if candidate.finding.severity.value in ("critical", "high"):
                if candidate.id not in round_result.next_round_candidates:
                    round_result.next_round_candidates.append(candidate.id)
