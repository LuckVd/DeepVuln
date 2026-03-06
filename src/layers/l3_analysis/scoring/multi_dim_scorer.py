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
        reachability_score = self.reachability_scorer.score(call_chain)
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

        # 5. Derive exploitability status
        exploitability_status = self._derive_status(final_score, final_confidence)

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

    def _derive_status(
        self,
        score: float,
        confidence: float,
    ) -> ExploitabilityStatus:
        """
        Derive exploitability status from score and confidence.

        Rules:
        - score >= exploitable_threshold → EXPLOITABLE
        - score <= not_exploitable_threshold → NOT_EXPLOITABLE
        - confidence < min_confidence → NEEDS_REVIEW
        - otherwise → CONDITIONAL or UNLIKELY
        """
        if confidence < self.config.min_confidence:
            return ExploitabilityStatus.NEEDS_REVIEW

        if score >= self.config.exploitable_threshold:
            return ExploitabilityStatus.EXPLOITABLE

        if score <= self.config.not_exploitable_threshold:
            return ExploitabilityStatus.NOT_EXPLOITABLE

        # Middle ground - check score range
        # Use (exploitable + not_exploitable) / 2 as the boundary
        middle_boundary = (self.config.exploitable_threshold + self.config.not_exploitable_threshold) / 2
        if score >= middle_boundary:
            return ExploitabilityStatus.CONDITIONAL
        else:
            return ExploitabilityStatus.UNLIKELY
