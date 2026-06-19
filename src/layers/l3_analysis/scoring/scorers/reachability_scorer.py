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
        reachability_result=None,
    ) -> DimensionScore:
        """
        Score based on reachability evidence.

        Prefers a precise ``reachability_result`` from CallGraphAnalyzer (BFS
        over the real call graph from entry points); falls back to the
        lightweight ``call_chain`` from context_builder; finally unavailable.

        Scoring logic:
        - reachable from HTTP entry → 1.0; CLI → 0.8; unknown entry → 0.6
        - not reachable → 0.1
        """
        if reachability_result is not None:
            return self._score_from_reachability_result(reachability_result)
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

    def _score_from_reachability_result(self, rr) -> DimensionScore:
        """Score from a precise CallGraphAnalyzer ReachabilityResult.

        ``rr`` carries is_reachable / entry_point_type / confidence / path —
        a stronger evidence source than the lightweight context_builder
        CallChainInfo. Uses getattr to avoid a hard dependency on the
        ReachabilityResult type.
        """
        is_reachable = getattr(rr, "is_reachable", False)
        rr_confidence = getattr(rr, "confidence", 0.0)
        entry_type = getattr(rr, "entry_point_type", None)
        path_len = getattr(rr, "path_length", 0)
        entry = (entry_type or "UNKNOWN").upper()

        if is_reachable:
            if entry == "HTTP":
                score = 1.0
            elif entry == "CLI":
                score = 0.8
            elif entry == "UNKNOWN":
                score = 0.6
            else:
                score = 0.7
            confidence = max(rr_confidence, 0.6)
        else:
            score = 0.1
            confidence = max(rr_confidence, 0.5)

        evidence = {
            "source": "call_graph_analyzer",
            "is_reachable": is_reachable,
            "entry_point_type": entry_type,
            "path_length": path_len,
            "path": getattr(rr, "call_chain", None) or list(getattr(rr, "path", []) or []),
            "score": score,
            "confidence": confidence,
        }
        logger.debug(
            f"Reachability (precise): reachable={is_reachable}, "
            f"entry={entry}, path_len={path_len} → score={score:.2f}"
        )
        return DimensionScore(
            dimension=ScoringDimension.REACHABILITY,
            score=score,
            confidence=confidence,
            available=True,
            evidence=evidence,
        )
