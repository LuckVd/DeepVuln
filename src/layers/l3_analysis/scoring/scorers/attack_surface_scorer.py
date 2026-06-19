"""
Attack surface scorer.

Evaluates exploitability based on attack surface entry point type.
"""

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.scoring.models import DimensionScore, ScoringDimension

logger = get_logger(__name__)


class AttackSurfaceScorer:
    """Score based on attack surface entry point type."""

    # Entry point type weights. Direct entry points score high; indirect
    # matches (from round_four._is_in_attack_surface tiers) carry a _SAME_FILE
    # or _IMPORTED suffix and are deliberately downweighted — they are weaker
    # evidence of actual reachability.
    ENTRY_POINT_WEIGHTS = {
        "HTTP": 1.0,  # Direct web endpoints - most exploitable
        "API": 1.0,
        "WEB": 1.0,
        "RPC": 0.9,
        "GRPC": 0.9,
        "MQ": 0.85,
        "WEBSOCKET": 0.8,
        "SCHEDULED": 0.7,
        "CRON": 0.7,
        "CLI": 0.7,  # CLI requires local access
        "DAEMON": 0.6,
        "FILE": 0.5,
        "LIBRARY": 0.3,  # Library functions require caller context
        "UNKNOWN": 0.5,  # Unknown type - medium risk
        # Indirect (tiered) matches - downweighted
        "HTTP_SAME_FILE": 0.55, "API_SAME_FILE": 0.55, "WEB_SAME_FILE": 0.55,
        "RPC_SAME_FILE": 0.5, "MQ_SAME_FILE": 0.5, "WEBSOCKET_SAME_FILE": 0.5,
        "SCHEDULED_SAME_FILE": 0.45, "CLI_SAME_FILE": 0.45, "DAEMON_SAME_FILE": 0.4,
        "FILE_SAME_FILE": 0.35, "SAME_FILE": 0.4,
        "HTTP_IMPORTED": 0.4, "API_IMPORTED": 0.4, "WEB_IMPORTED": 0.4,
        "RPC_IMPORTED": 0.35, "MQ_IMPORTED": 0.35, "IMPORTED": 0.35,
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

        # Higher confidence for direct, well-known types; lower for indirect
        # tiered matches and unknown types.
        if entry_type in self.ENTRY_POINT_WEIGHTS:
            if entry_type == "UNKNOWN":
                confidence = 0.5
                evidence["note"] = "Unknown entry point type - low confidence"
            elif "_SAME_FILE" in entry_type or "_IMPORTED" in entry_type or entry_type in ("SAME_FILE", "IMPORTED"):
                confidence = 0.5
                evidence["note"] = "Indirect attack-surface match - downweighted confidence"
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
