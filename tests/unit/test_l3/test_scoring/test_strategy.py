"""
Tests for fusion strategies (P5-01d).

Tests the strategies for combining multi-dimensional scores.
"""

import pytest

from src.layers.l3_analysis.scoring.models import (
    DimensionScore,
    FusionWeights,
    MultiDimConfig,
    ScoringDimension,
)
from src.layers.l3_analysis.scoring.strategy import (
    ConservativeStrategy,
    OptimisticStrategy,
    WeightedAverageStrategy,
    create_strategy,
)

# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def sample_weights():
    """Sample fusion weights."""
    return FusionWeights(
        codeql=0.35,
        reachability=0.25,
        taint_tracking=0.30,
        attack_surface=0.10,
    )


@pytest.fixture
def sample_config(sample_weights):
    """Sample multi-dim config."""
    return MultiDimConfig(
        weights=sample_weights,
    )


@pytest.fixture
def available_scores():
    """All dimensions available."""
    return (
        DimensionScore(
            dimension=ScoringDimension.CODEQL,
            score=0.9,
            confidence=0.8,
            available=True,
        ),
        DimensionScore(
            dimension=ScoringDimension.REACHABILITY,
            score=0.7,
            confidence=0.7,
            available=True,
        ),
        DimensionScore(
            dimension=ScoringDimension.TAINT_TRACKING,
            score=0.8,
            confidence=0.9,
            available=True,
        ),
        DimensionScore(
            dimension=ScoringDimension.ATTACK_SURFACE,
            score=1.0,
            confidence=0.9,
            available=True,
        ),
    )


@pytest.fixture
def partial_scores():
    """Some dimensions unavailable."""
    return (
        DimensionScore(
            dimension=ScoringDimension.CODEQL,
            score=0.9,
            confidence=0.8,
            available=True,
        ),
        DimensionScore(
            dimension=ScoringDimension.REACHABILITY,
            score=0.0,
            confidence=0.0,
            available=False,
        ),
        DimensionScore(
            dimension=ScoringDimension.TAINT_TRACKING,
            score=0.8,
            confidence=0.9,
            available=True,
        ),
        DimensionScore(
            dimension=ScoringDimension.ATTACK_SURFACE,
            score=0.0,
            confidence=0.0,
            available=False,
        ),
    )


# ============================================================
# WeightedAverageStrategy Tests
# ============================================================

class TestWeightedAverageStrategy:
    """Tests for WeightedAverageStrategy."""

    def test_compute_final_score_all_available(self, sample_weights, available_scores):
        """Test scoring with all dimensions available."""
        strategy = WeightedAverageStrategy(weights=sample_weights, config=MultiDimConfig())

        score = strategy.compute_final_score(*available_scores)

        # Expected: 0.35*0.9 + 0.25*0.7 + 0.30*0.8 + 0.10*1.0
        expected = 0.35 * 0.9 + 0.25 * 0.7 + 0.30 * 0.8 + 0.10 * 1.0
        assert abs(score - expected) < 0.001

    def test_compute_final_score_partial(self, sample_weights, partial_scores):
        """Test scoring with some dimensions unavailable."""
        strategy = WeightedAverageStrategy(weights=sample_weights, config=MultiDimConfig())

        score = strategy.compute_final_score(*partial_scores)

        # Only codeql and taint_tracking available
        # Should normalize: (0.35*0.9 + 0.30*0.8) / (0.35 + 0.30)
        expected = (0.35 * 0.9 + 0.30 * 0.8) / (0.35 + 0.30)
        assert abs(score - expected) < 0.001

    def test_compute_final_score_none_available(self, sample_weights):
        """Test scoring with no dimensions available."""
        strategy = WeightedAverageStrategy(weights=sample_weights, config=MultiDimConfig())

        none_scores = (
            DimensionScore(dimension=ScoringDimension.CODEQL, score=0, confidence=0, available=False),
            DimensionScore(dimension=ScoringDimension.REACHABILITY, score=0, confidence=0, available=False),
            DimensionScore(dimension=ScoringDimension.TAINT_TRACKING, score=0, confidence=0, available=False),
            DimensionScore(dimension=ScoringDimension.ATTACK_SURFACE, score=0, confidence=0, available=False),
        )

        score = strategy.compute_final_score(*none_scores)
        assert score == 0.5  # Neutral score when no data

    def test_compute_confidence(self, sample_weights, available_scores):
        """Test confidence computation."""
        strategy = WeightedAverageStrategy(weights=sample_weights, config=MultiDimConfig())

        confidence = strategy.compute_confidence(*available_scores)

        # All available = high confidence
        assert confidence > 0.8


# ============================================================
# ConservativeStrategy Tests
# ============================================================

class TestConservativeStrategy:
    """Tests for ConservativeStrategy."""

    def test_compute_final_score_min(self, sample_weights):
        """Test conservative strategy uses minimum score."""
        strategy = ConservativeStrategy(weights=sample_weights, config=MultiDimConfig())

        scores = (
            DimensionScore(dimension=ScoringDimension.CODEQL, score=0.9, confidence=0.8, available=True),
            DimensionScore(dimension=ScoringDimension.REACHABILITY, score=0.3, confidence=0.7, available=True),
            DimensionScore(dimension=ScoringDimension.TAINT_TRACKING, score=0.7, confidence=0.9, available=True),
            DimensionScore(dimension=ScoringDimension.ATTACK_SURFACE, score=0.5, confidence=0.9, available=True),
        )

        score = strategy.compute_final_score(*scores)

        # Should use minimum
        assert score == 0.3

    def test_compute_confidence_min(self, sample_weights):
        """Test conservative strategy uses minimum confidence."""
        strategy = ConservativeStrategy(weights=sample_weights, config=MultiDimConfig())

        scores = (
            DimensionScore(dimension=ScoringDimension.CODEQL, score=0.9, confidence=0.8, available=True),
            DimensionScore(dimension=ScoringDimension.REACHABILITY, score=0.3, confidence=0.5, available=True),
            DimensionScore(dimension=ScoringDimension.TAINT_TRACKING, score=0.7, confidence=0.9, available=True),
            DimensionScore(dimension=ScoringDimension.ATTACK_SURFACE, score=0.5, confidence=0.9, available=True),
        )

        confidence = strategy.compute_confidence(*scores)

        # Should use minimum
        assert confidence == 0.5


# ============================================================
# OptimisticStrategy Tests
# ============================================================

class TestOptimisticStrategy:
    """Tests for OptimisticStrategy."""

    def test_compute_final_score_max(self, sample_weights):
        """Test optimistic strategy uses maximum score."""
        strategy = OptimisticStrategy(weights=sample_weights, config=MultiDimConfig())

        scores = (
            DimensionScore(dimension=ScoringDimension.CODEQL, score=0.9, confidence=0.8, available=True),
            DimensionScore(dimension=ScoringDimension.REACHABILITY, score=0.3, confidence=0.7, available=True),
            DimensionScore(dimension=ScoringDimension.TAINT_TRACKING, score=0.7, confidence=0.9, available=True),
            DimensionScore(dimension=ScoringDimension.ATTACK_SURFACE, score=0.5, confidence=0.9, available=True),
        )

        score = strategy.compute_final_score(*scores)

        # Should use maximum
        assert score == 0.9

    def test_compute_confidence_max(self, sample_weights):
        """Test optimistic strategy uses maximum confidence."""
        strategy = OptimisticStrategy(weights=sample_weights, config=MultiDimConfig())

        scores = (
            DimensionScore(dimension=ScoringDimension.CODEQL, score=0.9, confidence=0.8, available=True),
            DimensionScore(dimension=ScoringDimension.REACHABILITY, score=0.3, confidence=0.5, available=True),
            DimensionScore(dimension=ScoringDimension.TAINT_TRACKING, score=0.7, confidence=0.9, available=True),
            DimensionScore(dimension=ScoringDimension.ATTACK_SURFACE, score=0.5, confidence=0.9, available=True),
        )

        confidence = strategy.compute_confidence(*scores)

        # Should use maximum
        assert confidence == 0.9


# ============================================================
# create_strategy Tests
# ============================================================

class TestCreateStrategy:
    """Tests for create_strategy factory function."""

    def test_create_weighted_average_strategy(self, sample_config):
        """Test creating weighted average strategy."""
        strategy = create_strategy(sample_config)

        assert isinstance(strategy, WeightedAverageStrategy)

    def test_create_conservative_strategy(self):
        """Test creating conservative strategy."""
        config = MultiDimConfig(strategy_name="conservative")
        strategy = create_strategy(config)

        assert isinstance(strategy, ConservativeStrategy)

    def test_create_optimistic_strategy(self):
        """Test creating optimistic strategy."""
        config = MultiDimConfig(strategy_name="optimistic")
        strategy = create_strategy(config)

        assert isinstance(strategy, OptimisticStrategy)

    def test_unknown_strategy_defaults_to_weighted_average(self):
        """Test unknown strategy name defaults to weighted average."""
        config = MultiDimConfig(strategy_name="unknown")
        strategy = create_strategy(config)

        assert isinstance(strategy, WeightedAverageStrategy)
