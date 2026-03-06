"""
Round Two Executor - Deep Tracking

Second round of multi-round audit: deep analysis of vulnerability candidates.

This round performs:
1. Data flow analysis using CodeQL (with real dataflow paths)
2. Deep audit using Agent
3. Taint propagation tracking with complete paths
4. Evidence collection and confidence update
5. Sanitizer detection and evaluation
"""

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.codeql import (
    CodeQLDataflowExecutor,
    DataflowAnalysisConfig,
    QueryGenerator,
)
from src.layers.l3_analysis.engines.codeql import CodeQLEngine
from src.layers.l3_analysis.rounds.dataflow import (
    DataFlowPath,
    DeepAnalysisResult,
    PathNode,
    SinkType,
    SourceType,
    TaintSink,
    TaintSource,
)
from src.layers.l3_analysis.rounds.models import (
    AnalysisDepth,
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

        # Initialize the real dataflow analyzer
        self._dataflow_analyzer: Any = None
        self._analyzer_initialized = False

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

    async def _initialize_dataflow_analyzer(self) -> None:
        """Initialize the CodeQL dataflow analyzer."""
        if self._analyzer_initialized:
            return

        # Determine language from source path
        language = self._detect_language()

        # Create dataflow analysis config
        config = DataflowAnalysisConfig(
            codeql_path="codeql",
            database_path=self._database_path,
            source_root=self.source_path,
            language=language,
            timeout=300,
            max_concurrent_queries=3,
            evaluate_sanitizers=True,
        )

        # Create the dataflow analyzer
        self._dataflow_analyzer = CodeQLDataflowExecutor(
            codeql_path=config.codeql_path,
            database_path=config.database_path,
            timeout=config.timeout,
            source_root=config.source_root,
        )

        self._analyzer_initialized = True
        self.logger.info(f"Dataflow analyzer initialized for language: {language}")

    def _detect_language(self) -> str:
        """Detect programming language from source path."""
        # Check for common file extensions
        extensions = {
            ".py": "python",
            ".java": "java",
            ".js": "javascript",
            ".ts": "typescript",
            ".go": "go",
            ".cs": "csharp",
            ".rb": "ruby",
        }

        for ext, lang in extensions.items():
            if list(self.source_path.rglob(f"*{ext}")):
                return lang

        # Default to python
        return "python"

    async def _run_codeql_analysis(
        self,
        candidates: list[VulnerabilityCandidate],
        round_result: RoundResult,
        coverage: CoverageStats,
    ) -> EngineStats:
        """
        Run CodeQL data flow analysis on candidates.

        This method now uses the real CodeQL dataflow analyzer to:
        1. Generate custom queries for each vulnerability candidate
        2. Execute the queries against the CodeQL database
        3. Parse SARIF results to extract complete data flow paths
        4. Detect and evaluate sanitizers along the paths
        5. Update candidate confidence based on findings
        """
        self.logger.info("Phase 1: CodeQL Data Flow Analysis (Real Implementation)")

        stats = EngineStats(
            engine="codeql",
            enabled=self._codeql_engine is not None or self._database_path is not None,
            start_time=datetime.now(UTC),
        )

        # Try to initialize the real dataflow analyzer
        if not self._analyzer_initialized and self._database_path:
            await self._initialize_dataflow_analyzer()

        # Check if we can use the real analyzer
        use_real_analyzer = (
            self._dataflow_analyzer is not None and
            self._database_path is not None and
            self._database_path.exists()
        )

        if not use_real_analyzer:
            self.logger.info("CodeQL database not available, using fallback analysis")
            stats.add_warning("CodeQL database not available - using inference-based analysis")
            # Fall back to the original inference-based approach
            return await self._run_codeql_analysis_fallback(candidates, round_result, coverage, stats)

        try:
            stats.executed = True
            self.logger.info(f"Running real CodeQL dataflow analysis on {len(candidates)} candidates")

            # Analyze each candidate with the real dataflow analyzer
            for candidate in candidates:
                try:
                    # Generate and execute CodeQL query for this candidate
                    dataflow_result = await self._run_single_dataflow_analysis(candidate)

                    if dataflow_result:
                        # Create deep analysis result
                        deep_result = DeepAnalysisResult(
                            id=f"deep-{uuid.uuid4().hex[:8]}",
                            candidate_id=candidate.id,
                            original_confidence=self.CONFIDENCE_MAP.get(
                                candidate.confidence, "medium"
                            ),
                            analysis_started=datetime.now(UTC),
                        )

                        # Add all dataflow paths found
                        for path in dataflow_result.get("paths", []):
                            deep_result.add_dataflow_path(path)

                        # Store CodeQL findings
                        deep_result.codeql_findings = {
                            "has_path": dataflow_result.get("total_paths", 0) > 0,
                            "path_complete": dataflow_result.get("complete_paths", 0) > 0,
                            "has_effective_sanitizer": dataflow_result.get("has_effective_sanitizer", False),
                            "query_executed": dataflow_result.get("query_executed", False),
                            "execution_time_ms": dataflow_result.get("execution_time_ms", 0),
                        }

                        # Add evidence to candidate
                        candidate.add_evidence("codeql", deep_result.to_prompt_context())
                        candidate.analyzed_in_rounds.append(2)

                        # Store in metadata
                        if "deep_results" not in candidate.metadata:
                            candidate.metadata["deep_results"] = {}
                        candidate.metadata["deep_results"]["codeql"] = {
                            **deep_result.model_dump(),
                            "dataflow_analysis": dataflow_result,
                        }

                        # Update candidate confidence based on dataflow analysis
                        if dataflow_result.get("complete_paths", 0) > 0:
                            if not dataflow_result.get("has_effective_sanitizer", False):
                                # Complete path without sanitizer = high confidence
                                candidate.confidence = ConfidenceLevel.HIGH
                            else:
                                # Has sanitizer = lower confidence
                                candidate.confidence = ConfidenceLevel.LOW
                        elif dataflow_result.get("total_paths", 0) > 0:
                            # Partial paths = medium confidence
                            candidate.confidence = ConfidenceLevel.MEDIUM

                        stats.findings_count += 1

                except Exception as e:
                    self.logger.warning(f"CodeQL dataflow analysis failed for candidate {candidate.id}: {e}")
                    stats.add_warning(f"Candidate {candidate.id}: {e}")

            stats.candidates_count = len(candidates)
            coverage.analyzed_targets += len(candidates)

            self.logger.info(
                f"CodeQL dataflow analysis complete: {stats.findings_count} findings, "
                f"{sum(1 for c in candidates if c.confidence == ConfidenceLevel.HIGH)} high confidence"
            )

        except Exception as e:
            self.logger.error(f"CodeQL dataflow analysis failed: {e}")
            stats.add_error(str(e))

        stats.end_time = datetime.now(UTC)
        if stats.start_time:
            stats.duration_seconds = (
                stats.end_time - stats.start_time
            ).total_seconds()

        return stats

    async def _run_single_dataflow_analysis(
        self,
        candidate: VulnerabilityCandidate,
    ) -> dict[str, Any] | None:
        """
        Run CodeQL dataflow analysis for a single vulnerability candidate.

        This method:
        1. Generates a custom CodeQL query for the candidate
        2. Executes the query against the CodeQL database
        3. Parses the SARIF results to extract data flow paths
        4. Detects sanitizers along the paths

        Args:
            candidate: Vulnerability candidate to analyze.

        Returns:
            Dictionary with dataflow analysis results.
        """
        if not self._dataflow_analyzer or not candidate.finding:
            return None

        try:
            # Generate query configuration
            query_generator = QueryGenerator(language=self._detect_language())
            query_config = query_generator.generate_from_finding(
                finding=candidate.finding,
                language=self._detect_language(),
            )

            # Execute the query
            result = await self._dataflow_analyzer.execute_query(
                config=query_config,
                database_path=self._database_path,
            )

            if not result.success:
                self.logger.warning(f"Dataflow query execution failed: {result.error_message}")
                return None

            # Process results
            return {
                "query_id": result.query_id,
                "query_executed": result.query_executed,
                "total_paths": result.total_paths,
                "complete_paths": result.complete_paths,
                "paths_with_sanitizers": result.paths_with_sanitizers,
                "has_effective_sanitizer": any(
                    p.has_effective_sanitizer for p in result.paths
                ) if result.paths else False,
                "paths": result.paths,
                "execution_time_ms": result.execution_time_ms,
            }

        except Exception as e:
            self.logger.error(f"Single dataflow analysis failed: {e}")
            return None

    async def _run_codeql_analysis_fallback(
        self,
        candidates: list[VulnerabilityCandidate],
        round_result: RoundResult,
        coverage: CoverageStats,
        stats: EngineStats,
    ) -> EngineStats:
        """
        Fallback analysis when CodeQL database is not available.

        Uses inference-based approach to estimate data flow paths.
        """
        self.logger.info("Using inference-based fallback analysis")

        stats.executed = True

        # Analyze each candidate with inference
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

                # Run inference-based data flow tracing
                dataflow_path = await self._trace_dataflow_inference(candidate)
                if dataflow_path:
                    deep_result.add_dataflow_path(dataflow_path)

                # Store CodeQL findings
                deep_result.codeql_findings = {
                    "has_path": dataflow_path is not None,
                    "path_complete": dataflow_path.is_complete if dataflow_path else False,
                    "method": "inference_fallback",
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
                self.logger.warning(f"Fallback analysis failed for candidate {candidate.id}: {e}")
                stats.add_warning(f"Candidate {candidate.id}: {e}")

        stats.candidates_count = len(candidates)
        coverage.analyzed_targets += len(candidates)

        stats.end_time = datetime.now(UTC)
        if stats.start_time:
            stats.duration_seconds = (
                stats.end_time - stats.start_time
            ).total_seconds()

        return stats

    async def _trace_dataflow_inference(
        self,
        candidate: VulnerabilityCandidate,
    ) -> DataFlowPath | None:
        """
        Trace data flow using inference (fallback when CodeQL is not available).

        This method creates an estimated data flow path based on the finding's
        characteristics. It's used as a fallback when CodeQL database is not
        available or when CodeQL analysis fails.

        Note: This is NOT a real dataflow analysis - it uses heuristics to
        estimate the source and sink based on vulnerability type.

        Args:
            candidate: The vulnerability candidate to analyze.

        Returns:
            Data flow path if can be inferred, None otherwise.
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

        # Create an inferred path (not complete since no real analysis)
        path = DataFlowPath(
            id=f"path-{uuid.uuid4().hex[:8]}",
            candidate_id=candidate.id,
            source=source,
            sink=sink,
            is_complete=False,  # Inferred paths are never complete
            analyzer="inference",  # Mark as inference-based
            path_confidence=0.3,  # Low confidence for inferred paths
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
