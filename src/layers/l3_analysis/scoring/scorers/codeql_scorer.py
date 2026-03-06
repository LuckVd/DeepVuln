"""
CodeQL dataflow scorer.

Evaluates exploitability based on CodeQL's taint dataflow analysis.
"""

from dataclasses import dataclass

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.models import Finding
from src.layers.l3_analysis.scoring.models import DimensionScore, ScoringDimension

logger = get_logger(__name__)


@dataclass
class CodeQLScorer:
    """Score based on CodeQL dataflow analysis."""

    min_confidence: float = 0.3

    def score(
        self,
        finding: Finding,
        codeql_dataflow: dict | None = None,
    ) -> DimensionScore:
        """
        Score based on CodeQL dataflow evidence.

        Scoring logic:
        - Full dataflow with source/sink → 0.8-1.0
        - Partial dataflow (source only) → 0.5-0.7
        - No dataflow → 0.0-0.2
        - Sanitizer in path → 0.0-0.3
        """
        if not codeql_dataflow:
            return DimensionScore(
                dimension=ScoringDimension.CODEQL,
                score=0.1,
                confidence=0.2,
                available=False,
                evidence={"reason": "No CodeQL dataflow available"},
            )

        # Check for full dataflow
        has_source = codeql_dataflow.get("has_source", False)
        has_sink = codeql_dataflow.get("has_sink", False)
        has_sanitizer = codeql_dataflow.get("has_sanitizer", False)
        path_length = codeql_dataflow.get("path_length", 0)

        evidence = {
            "has_source": has_source,
            "has_sink": has_sink,
            "has_sanitizer": has_sanitizer,
            "path_length": path_length,
        }

        # Calculate score
        if has_sanitizer:
            # Sanitizer detected - low exploitability
            sanitizer_effectiveness = codeql_dataflow.get("sanitizer_effectiveness", "unknown")
            if sanitizer_effectiveness == "full":
                score = 0.0
                confidence = 0.9
            elif sanitizer_effectiveness == "partial":
                score = 0.2
                confidence = 0.7
            else:
                score = 0.3
                confidence = 0.5
        elif has_source and has_sink:
            # Full dataflow - high exploitability
            # Shorter path = higher score
            path_factor = max(0.5, 1.0 - (path_length * 0.05))
            score = 0.9 * path_factor
            confidence = 0.8
        elif has_source or has_sink:
            # Partial dataflow - medium exploitability
            score = 0.5
            confidence = 0.5
        else:
            # No meaningful dataflow
            score = 0.2
            confidence = 0.3

        evidence["score"] = score
        evidence["confidence"] = confidence

        logger.debug(
            f"CodeQL scoring: source={has_source}, sink={has_sink}, "
            f"sanitizer={has_sanitizer} → score={score:.2f}"
        )

        return DimensionScore(
            dimension=ScoringDimension.CODEQL,
            score=score,
            confidence=confidence,
            available=True,
            evidence=evidence,
        )
