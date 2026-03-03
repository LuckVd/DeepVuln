"""
Dataflow Analyzer - Coordinates complete dataflow analysis workflow.

This module provides the main orchestrator for CodeQL-based dataflow analysis,
integrating query generation, execution, SARIF parsing, and sanitizer detection.
"""

import asyncio
import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.codeql import (
    CodeQLDataflowExecutor,
    DataflowResult,
    QueryGenerator,
    SanitizerDetector,
    SARIFParser,
    TaintTrackingConfig,
)
from src.layers.l3_analysis.codeql.query_generator import VulnerabilityCategory
from src.layers.l3_analysis.codeql.sanitizer_detector import SanitizerEffectiveness
from src.layers.l3_analysis.models import Finding
from src.layers.l3_analysis.rounds.dataflow import (
    DataFlowPath,
    DeepAnalysisResult,
    PathNode,
    Sanitizer,
    TaintSink,
    TaintSource,
)
from src.layers.l3_analysis.rounds.models import VulnerabilityCandidate

logger = get_logger(__name__)


@dataclass
class DataflowAnalysisConfig:
    """Configuration for dataflow analysis."""

    # CodeQL settings
    codeql_path: str = "codeql"
    database_path: Path | None = None
    source_root: Path | None = None
    language: str = "python"

    # Execution settings
    timeout: int = 300
    max_concurrent_queries: int = 3

    # Analysis settings
    min_confidence: float = 0.3
    include_partial_paths: bool = True
    evaluate_sanitizers: bool = True


@dataclass
class DataflowAnalysisResult:
    """Result of dataflow analysis for a vulnerability candidate."""

    # Candidate info
    candidate_id: str
    finding_id: str

    # Analysis results
    dataflow_paths: list[DataFlowPath] = field(default_factory=list)
    primary_path: DataFlowPath | None = None

    # Analysis metadata
    query_executed: bool = False
    query_id: str | None = None
    execution_time_ms: float = 0.0

    # Effectiveness
    has_complete_path: bool = False
    has_effective_sanitizer: bool = False
    sanitizer_details: list[dict[str, Any]] = field(default_factory=list)

    # Confidence update
    original_confidence: str = "medium"
    updated_confidence: str = "medium"
    confidence_reason: str = ""

    # Status
    success: bool = True
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "candidate_id": self.candidate_id,
            "finding_id": self.finding_id,
            "has_complete_path": self.has_complete_path,
            "has_effective_sanitizer": self.has_effective_sanitizer,
            "sanitizer_count": len(self.sanitizer_details),
            "query_executed": self.query_executed,
            "query_id": self.query_id,
            "execution_time_ms": self.execution_time_ms,
            "original_confidence": self.original_confidence,
            "updated_confidence": self.updated_confidence,
            "confidence_reason": self.confidence_reason,
            "success": self.success,
            "error_message": self.error_message,
        }


class DataflowAnalyzer:
    """
    Main orchestrator for CodeQL-based dataflow analysis.

    This class coordinates the complete dataflow analysis workflow:
    1. Generate CodeQL queries from vulnerability candidates
    2. Execute queries against CodeQL database
    3. Parse SARIF results to extract complete paths
    4. Detect and evaluate sanitizers
    5. Update vulnerability confidence based on findings
    """

    def __init__(self, config: DataflowAnalysisConfig):
        """
        Initialize the dataflow analyzer.

        Args:
            config: Configuration for dataflow analysis.
        """
        self.config = config

        # Initialize components
        self.query_generator = QueryGenerator(language=config.language)
        self.executor = CodeQLDataflowExecutor(
            codeql_path=config.codeql_path,
            database_path=config.database_path,
            timeout=config.timeout,
            source_root=config.source_root,
        )
        self.sanitizer_detector = SanitizerDetector(language=config.language)
        self.sarif_parser = SARIFParser(source_root=config.source_root)

        # State
        self._initialized = False

    async def initialize(self) -> bool:
        """
        Initialize the dataflow analyzer.

        Returns:
            True if initialization successful.
        """
        if self._initialized:
            return True

        logger.info("Initializing DataflowAnalyzer...")

        # Check CodeQL availability
        if not await self.executor.is_available():
            logger.warning("CodeQL CLI is not available - dataflow analysis will be limited")
            self._initialized = False
            return False

        # Check database
        if not self.config.database_path or not self.config.database_path.exists():
            logger.warning(f"CodeQL database not found: {self.config.database_path}")
            self._initialized = False
            return False

        self._initialized = True
        logger.info("DataflowAnalyzer initialized successfully")
        return True

    async def analyze_candidate(
        self,
        candidate: VulnerabilityCandidate,
    ) -> DataflowAnalysisResult:
        """
        Perform dataflow analysis on a vulnerability candidate.

        Args:
            candidate: Vulnerability candidate from Round 1.

        Returns:
            DataflowAnalysisResult with analysis findings.
        """
        result = DataflowAnalysisResult(
            candidate_id=candidate.id,
            finding_id=candidate.finding.id if candidate.finding else "",
            original_confidence=self._confidence_to_str(candidate.confidence),
        )

        start_time = datetime.now(UTC)

        try:
            # Check initialization
            if not self._initialized:
                if not await self.initialize():
                    result.success = False
                    result.error_message = "DataflowAnalyzer not initialized (CodeQL or database unavailable)"
                    # Fall back to basic analysis
                    return self._fallback_analysis(candidate, result)

            # Step 1: Generate CodeQL query configuration
            logger.debug(f"Generating query for candidate {candidate.id}")
            query_config = self.query_generator.generate_from_finding(
                finding=candidate.finding,
                language=self.config.language,
            )
            result.query_id = query_config.query_id

            # Step 2: Execute CodeQL query
            logger.info(f"Executing dataflow query: {query_config.query_id}")
            dataflow_result = await self.executor.execute_query(
                config=query_config,
                database_path=self.config.database_path,
            )

            result.query_executed = dataflow_result.success

            if not dataflow_result.success:
                result.error_message = dataflow_result.error_message
                return self._fallback_analysis(candidate, result)

            # Step 3: Process dataflow paths
            result.dataflow_paths = dataflow_result.paths

            if result.dataflow_paths:
                # Select primary path (most complete)
                result.primary_path = self._select_primary_path(result.dataflow_paths)
                result.has_complete_path = result.primary_path.is_complete if result.primary_path else False

            # Step 4: Analyze sanitizers
            if self.config.evaluate_sanitizers and result.primary_path:
                await self._analyze_sanitizers(result.primary_path, candidate, result)

            # Step 5: Update confidence
            self._update_confidence(candidate, result)

            result.success = True
            logger.info(
                f"Dataflow analysis complete for {candidate.id}: "
                f"{len(result.dataflow_paths)} paths, "
                f"complete={result.has_complete_path}, "
                f"sanitized={result.has_effective_sanitizer}"
            )

        except Exception as e:
            logger.error(f"Dataflow analysis failed for {candidate.id}: {e}")
            result.success = False
            result.error_message = str(e)
            return self._fallback_analysis(candidate, result)

        finally:
            end_time = datetime.now(UTC)
            result.execution_time_ms = (end_time - start_time).total_seconds() * 1000

        return result

    async def analyze_batch(
        self,
        candidates: list[VulnerabilityCandidate],
    ) -> list[DataflowAnalysisResult]:
        """
        Analyze multiple vulnerability candidates.

        Args:
            candidates: List of vulnerability candidates.

        Returns:
            List of analysis results.
        """
        # Filter candidates by confidence
        filtered = [
            c for c in candidates
            if self._get_confidence_value(c) >= self.config.min_confidence
        ]

        logger.info(f"Analyzing {len(filtered)} candidates (filtered from {len(candidates)})")

        # Process in parallel with limit
        semaphore = asyncio.Semaphore(self.config.max_concurrent_queries)

        async def analyze_with_limit(candidate: VulnerabilityCandidate) -> DataflowAnalysisResult:
            async with semaphore:
                return await self.analyze_candidate(candidate)

        tasks = [analyze_with_limit(c) for c in filtered]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle exceptions
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                final_results.append(DataflowAnalysisResult(
                    candidate_id=filtered[i].id,
                    finding_id="",
                    success=False,
                    error_message=str(result),
                ))
            else:
                final_results.append(result)

        return final_results

    async def _analyze_sanitizers(
        self,
        path: DataFlowPath,
        candidate: VulnerabilityCandidate,
        result: DataflowAnalysisResult,
    ) -> None:
        """Analyze sanitizers in the data flow path."""
        # Convert path nodes to dict format for sanitizer detection
        path_nodes = [
            {
                "file_path": node.location.file,
                "line": node.location.line,
                "column": node.location.column,
                "snippet": node.location.snippet,
                "expression": node.expression,
            }
            for node in path.path_nodes
        ]

        # Detect sanitizers
        sanitizers = self.sanitizer_detector.detect_in_path(path_nodes)

        # Evaluate effectiveness
        vuln_type = self._infer_vulnerability_type(candidate)
        is_effective, reason = self.sanitizer_detector.evaluate_effectiveness(
            sanitizers, vuln_type
        )

        result.has_effective_sanitizer = is_effective
        result.sanitizer_details = [s.to_dict() for s in sanitizers]

        # Update path sanitizers
        for san_match in sanitizers:
            sanitizer = Sanitizer(
                id=f"san_{hashlib.md5(str(san_match.location).encode()).hexdigest()[:8]}",
                location=san_match.location,
                sanitizer_type=self._map_sanitizer_type(san_match.category),
                effective=san_match.effectiveness == SanitizerEffectiveness.FULL,
                function_name=san_match.function_name,
            )
            path.sanitizers.append(sanitizer)

        if sanitizers:
            path.has_effective_sanitizer = any(s.effective for s in path.sanitizers)

    def _select_primary_path(self, paths: list[DataFlowPath]) -> DataFlowPath | None:
        """Select the primary (most complete) path from results."""
        if not paths:
            return None

        # Prefer complete paths
        complete = [p for p in paths if p.is_complete]
        if complete:
            # Return the one with most nodes
            return max(complete, key=lambda p: len(p.path_nodes))

        # Fall back to longest partial path
        if self.config.include_partial_paths:
            return max(paths, key=lambda p: len(p.path_nodes))

        return None

    def _update_confidence(
        self,
        candidate: VulnerabilityCandidate,
        result: DataflowAnalysisResult,
    ) -> None:
        """Update vulnerability confidence based on analysis results."""
        reasons = []

        if result.has_complete_path:
            reasons.append("complete data flow path confirmed")

        if result.has_effective_sanitizer:
            reasons.append("effective sanitizer detected")
        elif result.sanitizer_details:
            reasons.append("partial sanitization (may be bypassable)")

        if not result.dataflow_paths:
            reasons.append("no data flow paths found")

        # Calculate new confidence
        if result.has_complete_path and not result.has_effective_sanitizer:
            # Complete path without effective sanitizer = high confidence
            result.updated_confidence = "high"
        elif result.has_complete_path and result.has_effective_sanitizer:
            # Complete path but has sanitizer = low confidence
            result.updated_confidence = "low"
        elif result.dataflow_paths and not result.has_effective_sanitizer:
            # Partial path, no sanitizer = medium confidence
            result.updated_confidence = "medium"
        elif result.has_effective_sanitizer:
            # Has effective sanitizer = low confidence
            result.updated_confidence = "low"
        else:
            # Keep original
            result.updated_confidence = result.original_confidence

        result.confidence_reason = "; ".join(reasons) if reasons else "no change"

    def _fallback_analysis(
        self,
        candidate: VulnerabilityCandidate,
        result: DataflowAnalysisResult,
    ) -> DataflowAnalysisResult:
        """Perform fallback analysis when CodeQL is unavailable."""
        logger.info(f"Using fallback analysis for {candidate.id}")

        # Create a basic path from finding
        finding = candidate.finding

        if finding:
            # Create source
            source = TaintSource(
                id=f"src_{candidate.id[:8]}",
                location=finding.location,
                source_type=self._infer_source_type(finding),
                user_controlled=True,
            )

            # Create sink
            sink = TaintSink(
                id=f"sink_{candidate.id[:8]}",
                location=finding.location,
                sink_type=self._infer_sink_type(finding),
                dangerous_if_tainted=True,
            )

            # Create basic path
            path = DataFlowPath(
                id=f"path_{candidate.id[:8]}",
                candidate_id=candidate.id,
                source=source,
                sink=sink,
                is_complete=False,
                analyzer="fallback",
                path_confidence=0.3,
            )

            # Add nodes
            path.add_node(PathNode(
                location=finding.location,
                node_type="source",
            ))
            path.add_node(PathNode(
                location=finding.location,
                node_type="sink",
            ))

            result.dataflow_paths = [path]
            result.primary_path = path
            result.updated_confidence = result.original_confidence
            result.confidence_reason = "fallback analysis (CodeQL unavailable)"

        return result

    def _confidence_to_str(self, confidence) -> str:
        """Convert confidence enum to string."""
        if hasattr(confidence, 'value'):
            return confidence.value
        return str(confidence).lower()

    def _get_confidence_value(self, candidate: VulnerabilityCandidate) -> float:
        """Get numeric confidence value."""
        conf_map = {"high": 0.9, "medium": 0.6, "low": 0.3}
        conf_str = self._confidence_to_str(candidate.confidence)
        return conf_map.get(conf_str, 0.5)

    def _infer_vulnerability_type(self, candidate: VulnerabilityCandidate) -> str:
        """Infer vulnerability type from candidate."""
        if candidate.finding:
            title = (candidate.finding.title or "").lower()
            tags = [t.lower() for t in (candidate.finding.tags or [])]

            if any(kw in title or kw in tags for kw in ["sql", "sqli"]):
                return "sql_injection"
            if any(kw in title or kw in tags for kw in ["xss", "cross-site"]):
                return "xss"
            if any(kw in title or kw in tags for kw in ["command", "rce", "os command"]):
                return "command_injection"
            if any(kw in title or kw in tags for kw in ["path", "traversal", "lfi"]):
                return "path_traversal"

        return "generic"

    def _infer_source_type(self, finding: Finding) -> "SourceType":
        """Infer source type from finding."""
        from src.layers.l3_analysis.rounds.dataflow import SourceType

        title = (finding.title or "").lower()
        if any(kw in title for kw in ["sql", "xss", "command"]):
            return SourceType.HTTP_PARAM
        return SourceType.USER_INPUT

    def _infer_sink_type(self, finding: Finding) -> "SinkType":
        """Infer sink type from finding."""
        from src.layers.l3_analysis.rounds.dataflow import SinkType

        title = (finding.title or "").lower()
        if "sql" in title:
            return SinkType.SQL_QUERY
        if "xss" in title:
            return SinkType.HTTP_RESPONSE
        if "command" in title or "rce" in title:
            return SinkType.COMMAND_EXEC
        if "path" in title:
            return SinkType.FILE_READ
        return SinkType.SQL_QUERY

    def _map_sanitizer_type(self, category: str) -> "SanitizerType":
        """Map category to SanitizerType."""
        from src.layers.l3_analysis.rounds.dataflow import SanitizerType

        mapping = {
            "html_encode": SanitizerType.HTML_ENCODE,
            "sql_escape": SanitizerType.SQL_ESCAPE,
            "prepared_stmt": SanitizerType.PREPARED_STMT,
            "command_escape": SanitizerType.COMMAND_ESCAPE,
            "path_validate": SanitizerType.PATH_VALIDATE,
            "input_validate": SanitizerType.INPUT_VALIDATE,
            "type_cast": SanitizerType.TYPE_CAST,
        }
        return mapping.get(category, SanitizerType.INPUT_VALIDATE)

    def get_statistics(self) -> dict[str, Any]:
        """Get analyzer statistics."""
        return {
            "initialized": self._initialized,
            "codeql_available": self._initialized,
            "database_path": str(self.config.database_path) if self.config.database_path else None,
            "language": self.config.language,
        }
