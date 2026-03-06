"""
Fusion strategy for combining multi-dimensional scores.

This module provides strategies to combine evidence from multiple sources
into a unified exploitability score.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.scoring.models import (
    DimensionScore,
    FusionWeights,
    MultiDimConfig,
)

logger = get_logger(__name__)


class FusionStrategy(ABC):
    """Base class for fusion strategies."""

    @abstractmethod
    def compute_final_score(
        self,
        codeql: DimensionScore,
        reachability: DimensionScore,
        taint_tracking: DimensionScore,
        attack_surface: DimensionScore,
    ) -> float:
        """Compute the final combined score."""

    @abstractmethod
    def compute_confidence(
        self,
        codeql: DimensionScore,
        reachability: DimensionScore,
        taint_tracking: DimensionScore,
        attack_surface: DimensionScore,
    ) -> float:
        """Compute the overall confidence."""


@dataclass
class WeightedAverageStrategy(FusionStrategy):
    """Weighted average fusion strategy."""

    weights: FusionWeights
    config: MultiDimConfig

    def compute_final_score(
        self,
        codeql: DimensionScore,
        reachability: DimensionScore,
        taint_tracking: DimensionScore,
        attack_surface: DimensionScore,
    ) -> float:
        """
        Compute weighted average of available dimensions.

        Formula:
        final_score = Σ(weight_i * score_i) / Σ(weight_i)

        Missing dimensions are simply excluded from the calculation.
        """
        score = 0.0
        total_weight = 0.0

        if codeql.available:
            score += self.weights.codeql * codeql.score
            total_weight += self.weights.codeql

        if reachability.available:
            score += self.weights.reachability * reachability.score
            total_weight += self.weights.reachability

        if taint_tracking.available:
            score += self.weights.taint_tracking * taint_tracking.score
            total_weight += self.weights.taint_tracking

        if attack_surface.available:
            score += self.weights.attack_surface * attack_surface.score
            total_weight += self.weights.attack_surface

        # Normalize if some dimensions are missing
        if total_weight > 0:
            score = score / total_weight
        else:
            logger.warning("No dimensions available for scoring")
            score = 0.5  # Neutral score when no data

        return score

    def compute_confidence(
        self,
        codeql: DimensionScore,
        reachability: DimensionScore,
        taint_tracking: DimensionScore,
        attack_surface: DimensionScore,
    ) -> float:
        """
        Compute overall confidence based on:
        1. Number of available dimensions (more = higher confidence)
        2. Individual dimension confidences
        3. Confidence penalty for missing dimensions
        """
        dimensions = [codeql, reachability, taint_tracking, attack_surface]
        available = [d for d in dimensions if d.available]
        missing = [d for d in dimensions if not d.available]

        # Base confidence from available dimensions
        if available:
            avg_confidence = sum(d.confidence for d in available) / len(available)
        else:
            avg_confidence = 0.0

        # Penalty for missing dimensions (0.95 per missing - less aggressive)
        missing_penalty = 0.95 ** len(missing)

        # Boost for having more dimensions (less aggressive curve)
        if len(available) >= 3:
            dimension_boost = 1.0
        elif len(available) == 2:
            dimension_boost = 0.9
        elif len(available) == 1:
            dimension_boost = 0.75
        else:
            dimension_boost = 0.0

        final_confidence = avg_confidence * missing_penalty * dimension_boost

        return min(1.0, max(0.0, final_confidence))


@dataclass
class ConservativeStrategy(FusionStrategy):
    """Conservative fusion strategy - trust the worst case."""

    weights: FusionWeights
    config: MultiDimConfig

    def compute_final_score(
        self,
        codeql: DimensionScore,
        reachability: DimensionScore,
        taint_tracking: DimensionScore,
        attack_surface: DimensionScore,
    ) -> float:
        """
        Use the minimum score among available dimensions.

        This is conservative - if any dimension indicates low exploitability,
        the final score reflects that.
        """
        dimensions = [codeql, reachability, taint_tracking, attack_surface]
        available = [d.score for d in dimensions if d.available]

        if available:
            return min(available)
        return 0.5  # Neutral when no data

    def compute_confidence(
        self,
        codeql: DimensionScore,
        reachability: DimensionScore,
        taint_tracking: DimensionScore,
        attack_surface: DimensionScore,
    ) -> float:
        """Use the minimum confidence among available dimensions."""
        dimensions = [codeql, reachability, taint_tracking, attack_surface]
        available = [d.confidence for d in dimensions if d.available]

        if available:
            return min(available)
        return 0.0


@dataclass
class OptimisticStrategy(FusionStrategy):
    """Optimistic fusion strategy - trust the best case."""

    weights: FusionWeights
    config: MultiDimConfig

    def compute_final_score(
        self,
        codeql: DimensionScore,
        reachability: DimensionScore,
        taint_tracking: DimensionScore,
        attack_surface: DimensionScore,
    ) -> float:
        """Use the maximum score among available dimensions."""
        dimensions = [codeql, reachability, taint_tracking, attack_surface]
        available = [d.score for d in dimensions if d.available]

        if available:
            return max(available)
        return 0.5  # Neutral when no data

    def compute_confidence(
        self,
        codeql: DimensionScore,
        reachability: DimensionScore,
        taint_tracking: DimensionScore,
        attack_surface: DimensionScore,
    ) -> float:
        """Use the maximum confidence among available dimensions."""
        dimensions = [codeql, reachability, taint_tracking, attack_surface]
        available = [d.confidence for d in dimensions if d.available]

        if available:
            return max(available)
        return 0.0


def create_strategy(config: MultiDimConfig) -> FusionStrategy:
    """Create a fusion strategy based on configuration."""
    weights = config.weights.normalize()

    if config.strategy_name == "weighted_average":
        return WeightedAverageStrategy(weights=weights, config=config)
    elif config.strategy_name == "conservative":
        return ConservativeStrategy(weights=weights, config=config)
    elif config.strategy_name == "optimistic":
        return OptimisticStrategy(weights=weights, config=config)
    else:
        logger.warning(f"Unknown strategy: {config.strategy_name}, using weighted_average")
        return WeightedAverageStrategy(weights=weights, config=config)
