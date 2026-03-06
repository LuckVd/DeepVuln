"""
Multi-dimensional scoring models for exploitability assessment.

This module provides data models for integrating evidence from multiple sources:
- CodeQL dataflow analysis
- AST call graph reachability
- Taint tracking with sanitizer detection
- Attack surface entry point analysis
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.layers.l3_analysis.rounds.round_four import ExploitabilityStatus


class ScoringDimension(str, Enum):
    """Scoring dimension identifiers."""

    CODEQL = "codeql"
    REACHABILITY = "reachability"
    TAINT_TRACKING = "taint_tracking"
    ATTACK_SURFACE = "attack_surface"


@dataclass
class DimensionScore:
    """Score for a single dimension."""

    dimension: str  # Dimension identifier
    score: float  # Score (0-1)
    confidence: float  # Confidence (0-1)
    available: bool  # Whether this dimension is available
    evidence: dict[str, Any] = field(default_factory=dict)  # Raw evidence

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "dimension": self.dimension,
            "score": self.score,
            "confidence": self.confidence,
            "available": self.available,
            "evidence": self.evidence,
        }


@dataclass
class FusionWeights:
    """Fusion weights for combining dimensions."""

    codeql: float = 0.60  # CodeQL dataflow weight (increased for primary influence)
    reachability: float = 0.15  # Call graph reachability weight
    taint_tracking: float = 0.20  # Taint tracking weight
    attack_surface: float = 0.05  # Attack surface weight

    def normalize(self) -> "FusionWeights":
        """Normalize weights to sum to 1."""
        total = self.codeql + self.reachability + self.taint_tracking + self.attack_surface
        if total == 0:
            return self
        return FusionWeights(
            codeql=self.codeql / total,
            reachability=self.reachability / total,
            taint_tracking=self.taint_tracking / total,
            attack_surface=self.attack_surface / total,
        )

    def to_dict(self) -> dict[str, float]:
        """Convert to dictionary."""
        return {
            "codeql": self.codeql,
            "reachability": self.reachability,
            "taint_tracking": self.taint_tracking,
            "attack_surface": self.attack_surface,
        }


@dataclass
class MultiDimScore:
    """Multi-dimensional combined score."""

    # Individual dimension scores
    codeql: DimensionScore
    reachability: DimensionScore
    taint_tracking: DimensionScore
    attack_surface: DimensionScore

    # Fusion results
    final_score: float  # Combined score (0-1)
    final_confidence: float  # Combined confidence (0-1)

    # Metadata
    strategy_used: str  # Name of fusion strategy used
    dimensions_used: list[str] = field(default_factory=list)  # Available dimensions
    missing_dimensions: list[str] = field(default_factory=list)  # Unavailable dimensions

    # Derived exploitability status
    exploitability_status: ExploitabilityStatus = ExploitabilityStatus.NEEDS_REVIEW

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "dimensions": {
                "codeql": self.codeql.to_dict(),
                "reachability": self.reachability.to_dict(),
                "taint_tracking": self.taint_tracking.to_dict(),
                "attack_surface": self.attack_surface.to_dict(),
            },
            "final_score": self.final_score,
            "final_confidence": self.final_confidence,
            "strategy_used": self.strategy_used,
            "dimensions_used": self.dimensions_used,
            "missing_dimensions": self.missing_dimensions,
            "exploitability_status": self.exploitability_status.value,
        }

    def get_dimension(self, dimension: str) -> DimensionScore:
        """Get score for a specific dimension."""
        if dimension == ScoringDimension.CODEQL:
            return self.codeql
        elif dimension == ScoringDimension.REACHABILITY:
            return self.reachability
        elif dimension == ScoringDimension.TAINT_TRACKING:
            return self.taint_tracking
        elif dimension == ScoringDimension.ATTACK_SURFACE:
            return self.attack_surface
        raise ValueError(f"Unknown dimension: {dimension}")


@dataclass
class MultiDimConfig:
    """Configuration for multi-dimensional scoring."""

    strategy_name: str = "weighted_average"
    weights: FusionWeights = field(default_factory=FusionWeights)
    min_confidence: float = 0.2  # Minimum confidence to trust a score (lowered for partial data)
    require_min_dimensions: int = 1  # Minimum dimensions required (lowered for better coverage)

    # Scoring thresholds
    exploitable_threshold: float = 0.6  # Score above this = exploitable (lowered for better coverage)
    not_exploitable_threshold: float = 0.3  # Score below this = not exploitable

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "strategy_name": self.strategy_name,
            "weights": self.weights.to_dict(),
            "min_confidence": self.min_confidence,
            "require_min_dimensions": self.require_min_dimensions,
            "exploitable_threshold": self.exploitable_threshold,
            "not_exploitable_threshold": self.not_exploitable_threshold,
        }
