"""Scoring module for multi-dimensional exploitability assessment."""

from src.layers.l3_analysis.scoring.models import (
    DimensionScore,
    FusionWeights,
    MultiDimConfig,
    MultiDimScore,
    ScoringDimension,
)
from src.layers.l3_analysis.scoring.strategy import (
    ConservativeStrategy,
    FusionStrategy,
    OptimisticStrategy,
    WeightedAverageStrategy,
    create_strategy,
)

__all__ = [
    # Models
    "DimensionScore",
    "FusionWeights",
    "MultiDimConfig",
    "MultiDimScore",
    "ScoringDimension",
    # Strategies
    "FusionStrategy",
    "WeightedAverageStrategy",
    "ConservativeStrategy",
    "OptimisticStrategy",
    "create_strategy",
]
