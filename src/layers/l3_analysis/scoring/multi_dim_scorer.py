"""
Multi-dimensional scorer - Main orchestrator.

Integrates evidence from multiple dimensions to produce a unified exploitability score.
"""


from src.core.logger.logger import get_logger
from src.layers.l3_analysis.call_graph.models import TaintTraceResult
from src.layers.l3_analysis.models import Finding
from src.layers.l3_analysis.rounds.round_four import ExploitabilityStatus
from src.layers.l3_analysis.scoring.models import (
    DimensionScore,
    MultiDimConfig,
    MultiDimScore,
    ScoringDimension,
)
from src.layers.l3_analysis.scoring.scorers.attack_surface_scorer import AttackSurfaceScorer
from src.layers.l3_analysis.scoring.scorers.codeql_scorer import CodeQLScorer
from src.layers.l3_analysis.scoring.scorers.reachability_scorer import ReachabilityScorer
from src.layers.l3_analysis.scoring.scorers.taint_scorer import TaintTrackingScorer
from src.layers.l3_analysis.scoring.strategy import FusionStrategy, create_strategy
from src.layers.l3_analysis.task.context_builder import CallChainInfo

logger = get_logger(__name__)


class MultiDimScorer:
    """
    Multi-dimensional exploitability scorer.

    Combines evidence from:
    - CodeQL dataflow analysis
    - AST call graph reachability
    - Taint tracking with sanitizer detection
    - Attack surface entry point analysis
    """

    def __init__(
        self,
        config: MultiDimConfig | None = None,
        strategy: FusionStrategy | None = None,
    ):
        """
        Initialize the multi-dimensional scorer.

        Args:
            config: Scoring configuration
            strategy: Fusion strategy (created from config if None)
        """
        self.config = config or MultiDimConfig()
        self.strategy = strategy or create_strategy(self.config)

        # Initialize individual scorers
        self.codeql_scorer = CodeQLScorer()
        self.taint_scorer = TaintTrackingScorer()
        self.reachability_scorer = ReachabilityScorer()
        self.attack_surface_scorer = AttackSurfaceScorer()

        logger.info(
            f"MultiDimScorer initialized with strategy: {self.config.strategy_name}"
        )

    def score_candidate(
        self,
        finding: Finding,
        codeql_dataflow: dict | None = None,
        taint_trace_result: TaintTraceResult | None = None,
        call_chain: CallChainInfo | None = None,
        attack_surface_type: str | None = None,
        reachability_result=None,
    ) -> MultiDimScore:
        """
        Compute multi-dimensional score for a vulnerability candidate.

        Args:
            finding: The vulnerability finding
            codeql_dataflow: CodeQL dataflow evidence (optional)
            taint_trace_result: Taint tracking result (optional)
            call_chain: Call chain information (optional)
            attack_surface_type: Attack surface entry point type (optional)

        Returns:
            MultiDimScore with combined score and status
        """
        logger.debug(f"Scoring candidate: {finding.id}")

        # 1. Score each dimension
        codeql_score = self.codeql_scorer.score(finding, codeql_dataflow)
        taint_score = self.taint_scorer.score(taint_trace_result)
        reachability_score = self.reachability_scorer.score(call_chain, reachability_result)
        attack_surface_score = self.attack_surface_scorer.score(attack_surface_type)

        # 2. Compute fused score
        final_score = self.strategy.compute_final_score(
            codeql_score, reachability_score, taint_score, attack_surface_score
        )

        # 3. Compute overall confidence
        final_confidence = self._compute_confidence([
            codeql_score, reachability_score, taint_score, attack_surface_score
        ])

        # 4. Determine available/missing dimensions
        dimensions = [codeql_score, reachability_score, taint_score, attack_surface_score]
        dimensions_used = [d.dimension for d in dimensions if d.available]
        missing_dimensions = [d.dimension for d in dimensions if not d.available]

        # 5. Derive exploitability status (Phase 18/P6: evidence gate reads
        # dimension evidence conclusions, not just availability).
        (
            exploitability_status,
            confirming_count,
            supporting_count,
        ) = self._derive_status(final_score, final_confidence, dimensions)

        # 6. Build result
        result = MultiDimScore(
            codeql=codeql_score,
            reachability=reachability_score,
            taint_tracking=taint_score,
            attack_surface=attack_surface_score,
            final_score=final_score,
            final_confidence=final_confidence,
            strategy_used=self.config.strategy_name,
            dimensions_used=dimensions_used,
            missing_dimensions=missing_dimensions,
            exploitability_status=exploitability_status,
            confirming_evidence_count=confirming_count,
            supporting_evidence_count=supporting_count,
        )

        logger.info(
            f"Scoring complete: {finding.id} → "
            f"score={final_score:.2f}, status={exploitability_status.value}, "
            f"dimensions={len(dimensions_used)}/4"
        )

        return result

    def _compute_confidence(self, scores: list[DimensionScore]) -> float:
        """
        Compute overall confidence from dimension scores.

        Uses the strategy's confidence computation.
        """
        return self.strategy.compute_confidence(
            scores[0], scores[1], scores[2], scores[3]
        )

    def _classify_evidence(
        self, dimensions: list[DimensionScore]
    ) -> tuple[int, int]:
        """Classify each dimension's evidence as confirming or supporting.

        Phase 18/P6: the gate reads evidence *conclusions*, not just whether
        a dimension ran (``available``). Returns ``(confirming, supporting)``
        counts. A dimension contributes to at most one tier (confirming takes
        precedence); only ``available`` dimensions with real conclusions count.

        - confirming (dataflow-grade): CodeQL reports source AND sink with no
          sanitizer, or taint tracking marks the candidate exploitable.
        - supporting (reachability-grade): taint reachable-but-not-exploitable
          and unsanitized, or call-graph reachability confirms reachable.
        - attack_surface is a label, never evidence → skipped.
        """
        confirming = 0
        supporting = 0
        for dim in dimensions:
            if not dim.available:
                continue
            ev = dim.evidence or {}
            if dim.dimension == ScoringDimension.CODEQL.value:
                if ev.get("has_source") and ev.get("has_sink") and not ev.get(
                    "has_sanitizer"
                ):
                    confirming += 1
            elif dim.dimension == ScoringDimension.TAINT_TRACKING.value:
                if ev.get("is_exploitable"):
                    confirming += 1
                elif ev.get("is_reachable") and not ev.get("is_sanitized"):
                    supporting += 1
            elif dim.dimension == ScoringDimension.REACHABILITY.value:
                # Precise mode carries is_reachable; lightweight mode carries
                # is_entry_point / caller_count. Any of them => reachable.
                if ev.get("is_reachable") or ev.get("is_entry_point") or (
                    ev.get("caller_count", 0) > 0
                ):
                    supporting += 1
            # attack_surface: label, skipped.
        return confirming, supporting

    def _derive_status(
        self,
        score: float,
        confidence: float,
        dimensions: list[DimensionScore] | None = None,
    ) -> tuple[ExploitabilityStatus, int, int]:
        """Derive exploitability status from score, confidence, and evidence.

        Phase 18/P6 evidence gate: reads each dimension's evidence conclusion
        (confirming vs supporting), not merely availability. Returns
        ``(status, confirming_count, supporting_count)``.

        Rules (with ``require_confirming_for_exploitable=True``):
        - confidence < min_confidence → NEEDS_REVIEW
        - score >= exploitable_threshold → EXPLOITABLE only with >=1
          confirming dimension; supporting-only (no confirming) → CONDITIONAL;
          neither → NEEDS_REVIEW.
        - score <= not_exploitable_threshold → NOT_EXPLOITABLE
        - middle ground → CONDITIONAL if any confirming/supporting, else
          CONDITIONAL/UNLIKELY split by the middle boundary.

        With ``require_confirming_for_exploitable=False`` (legacy escape
        hatch), any confirming-or-supporting dimension confirms EXPLOITABLE.
        """
        confirming, supporting = self._classify_evidence(dimensions or [])

        if confidence < self.config.min_confidence:
            return ExploitabilityStatus.NEEDS_REVIEW, confirming, supporting

        if score >= self.config.exploitable_threshold:
            if self.config.require_confirming_for_exploitable:
                if confirming >= 1:
                    return ExploitabilityStatus.EXPLOITABLE, confirming, supporting
                if supporting >= 1:
                    return ExploitabilityStatus.CONDITIONAL, confirming, supporting
                return ExploitabilityStatus.NEEDS_REVIEW, confirming, supporting
            # Legacy: any dataflow/reachability evidence confirms.
            if confirming + supporting >= 1:
                return ExploitabilityStatus.EXPLOITABLE, confirming, supporting
            return ExploitabilityStatus.NEEDS_REVIEW, confirming, supporting

        if score <= self.config.not_exploitable_threshold:
            return ExploitabilityStatus.NOT_EXPLOITABLE, confirming, supporting

        # Middle ground: score between thresholds. The evidence gate governs
        # only the EXPLOITABLE decision at/above the threshold; here the score
        # alone splits CONDITIONAL / UNLIKELY at the mid-point.
        middle_boundary = (
            self.config.exploitable_threshold + self.config.not_exploitable_threshold
        ) / 2
        if score >= middle_boundary:
            return ExploitabilityStatus.CONDITIONAL, confirming, supporting
        return ExploitabilityStatus.UNLIKELY, confirming, supporting
