"""
Reachability scorer.

Evaluates exploitability based on call graph reachability analysis.
"""

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.scoring.models import DimensionScore, ScoringDimension
from src.layers.l3_analysis.task.context_builder import CallChainInfo

logger = get_logger(__name__)


class ReachabilityScorer:
    """Score based on call graph reachability analysis."""

    def score(
        self,
        call_chain: CallChainInfo | None = None,
    ) -> DimensionScore:
        """
        Score based on reachability evidence.

        Scoring logic:
        - is_entry_point = True → 0.8-1.0
        - Has callers → 0.5-0.7
        - No callers (isolated) → 0.0-0.2
        """
        if not call_chain:
            return DimensionScore(
                dimension=ScoringDimension.REACHABILITY,
                score=0.2,
                confidence=0.3,
                available=False,
                evidence={"reason": "No call chain info available"},
            )

        evidence = {
            "is_entry_point": call_chain.is_entry_point,
            "entry_point_type": call_chain.entry_point_type,
            "caller_count": len(call_chain.callers) if call_chain.callers else 0,
        }

        # Calculate score
        if call_chain.is_entry_point:
            # Direct entry point - high exploitability
            entry_type = call_chain.entry_point_type or "UNKNOWN"

            # Different entry types have different weights
            if entry_type == "HTTP":
                score = 1.0
                confidence = 0.95
            elif entry_type == "CLI":
                score = 0.8
                confidence = 0.85
            elif entry_type == "UNKNOWN":
                score = 0.6
                confidence = 0.5
            else:
                score = 0.7
                confidence = 0.6

        elif call_chain.callers and len(call_chain.callers) > 0:
            # Has callers - reachable from somewhere
            caller_count = len(call_chain.callers)
            # More callers = higher score (up to a point)
            score = min(0.7, 0.3 + (caller_count * 0.1))
            confidence = 0.7

        else:
            # No callers - isolated function
            score = 0.1
            confidence = 0.6

        evidence["score"] = score
        evidence["confidence"] = confidence

        logger.debug(
            f"Reachability scoring: entry_point={call_chain.is_entry_point}, "
            f"type={call_chain.entry_point_type}, callers={evidence['caller_count']} "
            f"→ score={score:.2f}"
        )

        return DimensionScore(
            dimension=ScoringDimension.REACHABILITY,
            score=score,
            confidence=confidence,
            available=True,
            evidence=evidence,
        )
