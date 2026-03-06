"""
Attack surface scorer.

Evaluates exploitability based on attack surface entry point type.
"""

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.scoring.models import DimensionScore, ScoringDimension

logger = get_logger(__name__)


class AttackSurfaceScorer:
    """Score based on attack surface entry point type."""

    # Entry point type weights
    ENTRY_POINT_WEIGHTS = {
        "HTTP": 1.0,  # Web endpoints are most exploitable
        "API": 1.0,
        "WEB": 1.0,
        "CLI": 0.7,  # CLI requires local access
        "DAEMON": 0.6,
        "LIBRARY": 0.3,  # Library functions require caller context
        "UNKNOWN": 0.5,  # Unknown type - medium risk
    }

    def score(
        self,
        entry_point_type: str | None = None,
    ) -> DimensionScore:
        """
        Score based on attack surface evidence.

        Scoring logic:
        - HTTP/API → 1.0 (highest exploitability)
        - CLI → 0.7
        - Library → 0.3
        - Unknown → 0.5
        """
        if not entry_point_type:
            return DimensionScore(
                dimension=ScoringDimension.ATTACK_SURFACE,
                score=0.5,
                confidence=0.3,
                available=False,
                evidence={"reason": "No entry point type available"},
            )

        # Normalize entry point type
        entry_type = entry_point_type.upper()
        weight = self.ENTRY_POINT_WEIGHTS.get(entry_type, 0.5)

        evidence = {
            "entry_point_type": entry_point_type,
            "weight": weight,
        }

        # Higher confidence for well-known types (except UNKNOWN which is uncertain)
        if entry_type in self.ENTRY_POINT_WEIGHTS:
            if entry_type == "UNKNOWN":
                confidence = 0.5
                evidence["note"] = "Unknown entry point type - low confidence"
            else:
                confidence = 0.9
        else:
            confidence = 0.5
            evidence["note"] = "Unknown entry point type"

        evidence["confidence"] = confidence

        logger.debug(
            f"Attack surface scoring: type={entry_point_type}, "
            f"weight={weight:.2f} → score={weight:.2f}"
        )

        return DimensionScore(
            dimension=ScoringDimension.ATTACK_SURFACE,
            score=weight,
            confidence=confidence,
            available=True,
            evidence=evidence,
        )
