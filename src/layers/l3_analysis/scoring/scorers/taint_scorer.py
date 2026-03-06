"""
Taint tracking scorer.

Evaluates exploitability based on call graph taint tracking with sanitizer detection.
"""

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.call_graph.models import TaintTraceResult
from src.layers.l3_analysis.scoring.models import DimensionScore, ScoringDimension

logger = get_logger(__name__)


class TaintTrackingScorer:
    """Score based on taint tracking analysis."""

    def score(
        self,
        taint_trace_result: TaintTraceResult | None = None,
    ) -> DimensionScore:
        """
        Score based on taint tracking evidence.

        Scoring logic:
        - is_exploitable = True → 0.9-1.0
        - is_reachable + not_sanitized → 0.7-0.9
        - is_sanitized → 0.0-0.2
        - not_reachable → 0.0
        """
        if not taint_trace_result:
            return DimensionScore(
                dimension=ScoringDimension.TAINT_TRACKING,
                score=0.0,
                confidence=0.0,
                available=False,
                evidence={"reason": "No taint tracking result available"},
            )

        evidence = {
            "is_reachable": taint_trace_result.is_reachable,
            "is_sanitized": taint_trace_result.is_sanitized,
            "is_exploitable": taint_trace_result.is_exploitable,
            "path_length": taint_trace_result.path_length,
            "sanitizer_count": len(taint_trace_result.sanitizers),
        }

        # Calculate score
        if taint_trace_result.is_exploitable:
            # Direct exploitable - highest score
            score = 0.95
            # Adjust for path length (shorter = higher)
            path_factor = max(0.8, 1.0 - (taint_trace_result.path_length * 0.02))
            score = score * path_factor
            confidence = taint_trace_result.confidence

        elif taint_trace_result.is_sanitized:
            # Sanitizer detected - low exploitability
            if taint_trace_result.effective_sanitizer:
                eff = taint_trace_result.effective_sanitizer
                if eff.combined_confidence > 0.8:
                    score = 0.0
                else:
                    score = 0.2
            else:
                score = 0.1
            confidence = taint_trace_result.confidence

        elif taint_trace_result.is_reachable:
            # Reachable but sanitizer status unclear
            score = 0.6
            confidence = taint_trace_result.confidence * 0.8

        else:
            # Not reachable from entry points
            score = 0.0
            confidence = taint_trace_result.confidence

        evidence["score"] = score
        evidence["confidence"] = confidence

        logger.debug(
            f"Taint tracking scoring: reachable={taint_trace_result.is_reachable}, "
            f"sanitized={taint_trace_result.is_sanitized}, "
            f"exploitable={taint_trace_result.is_exploitable} → score={score:.2f}"
        )

        return DimensionScore(
            dimension=ScoringDimension.TAINT_TRACKING,
            score=score,
            confidence=confidence,
            available=True,
            evidence=evidence,
        )
