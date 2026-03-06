"""
Tests for multi-dimensional scoring models (P5-01d).

Tests the data models for multi-dimensional exploitability scoring.
"""

import pytest

from src.layers.l3_analysis.rounds.round_four import ExploitabilityStatus
from src.layers.l3_analysis.scoring.models import (
    DimensionScore,
    FusionWeights,
    MultiDimConfig,
    MultiDimScore,
    ScoringDimension,
)

# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def sample_dimension_score():
    """Sample dimension score."""
    return DimensionScore(
        dimension=ScoringDimension.CODEQL,
        score=0.8,
        confidence=0.9,
        available=True,
        evidence={"has_source": True, "has_sink": True},
    )


@pytest.fixture
def sample_fusion_weights():
    """Sample fusion weights."""
    return FusionWeights(
        codeql=0.35,
        reachability=0.25,
        taint_tracking=0.30,
        attack_surface=0.10,
    )


@pytest.fixture
def sample_multi_dim_config():
    """Sample multi-dim config."""
    return MultiDimConfig(
        strategy_name="weighted_average",
        exploitable_threshold=0.7,
        not_exploitable_threshold=0.3,
    )


# ============================================================
# DimensionScore Tests
# ============================================================

class TestDimensionScore:
    """Tests for DimensionScore model."""

    def test_create_dimension_score(self):
        """Test creating a dimension score."""
        score = DimensionScore(
            dimension=ScoringDimension.CODEQL,
            score=0.8,
            confidence=0.9,
            available=True,
            evidence={"test": "data"},
        )

        assert score.dimension == ScoringDimension.CODEQL
        assert score.score == 0.8
        assert score.confidence == 0.9
        assert score.available is True
        assert score.evidence == {"test": "data"}

    def test_dimension_score_to_dict(self, sample_dimension_score):
        """Test DimensionScore serialization."""
        result_dict = sample_dimension_score.to_dict()

        assert isinstance(result_dict, dict)
        assert result_dict["dimension"] == ScoringDimension.CODEQL
        assert result_dict["score"] == 0.8
        assert result_dict["confidence"] == 0.9
        assert result_dict["available"] is True
        assert "evidence" in result_dict


# ============================================================
# FusionWeights Tests
# ============================================================

class TestFusionWeights:
    """Tests for FusionWeights model."""

    def test_default_weights(self):
        """Test default weight values."""
        weights = FusionWeights()

        assert weights.codeql == 0.60
        assert weights.reachability == 0.15
        assert weights.taint_tracking == 0.20
        assert weights.attack_surface == 0.05

    def test_normalize_weights(self):
        """Test weight normalization."""
        weights = FusionWeights(
            codeql=0.5,
            reachability=0.3,
            taint_tracking=0.2,
            attack_surface=0.0,
        )

        normalized = weights.normalize()

        total = (
            normalized.codeql
            + normalized.reachability
            + normalized.taint_tracking
            + normalized.attack_surface
        )

        assert abs(total - 1.0) < 0.001

    def test_weights_to_dict(self, sample_fusion_weights):
        """Test FusionWeights serialization."""
        result_dict = sample_fusion_weights.to_dict()

        assert isinstance(result_dict, dict)
        assert result_dict["codeql"] == 0.35
        assert result_dict["reachability"] == 0.25


# ============================================================
# MultiDimConfig Tests
# ============================================================

class TestMultiDimConfig:
    """Tests for MultiDimConfig model."""

    def test_default_config(self):
        """Test default configuration."""
        config = MultiDimConfig()

        assert config.strategy_name == "weighted_average"
        assert config.exploitable_threshold == 0.6
        assert config.not_exploitable_threshold == 0.3

    def test_config_to_dict(self, sample_multi_dim_config):
        """Test MultiDimConfig serialization."""
        result_dict = sample_multi_dim_config.to_dict()

        assert isinstance(result_dict, dict)
        assert "strategy_name" in result_dict
        assert "weights" in result_dict
        assert "exploitable_threshold" in result_dict


# ============================================================
# MultiDimScore Tests
# ============================================================

class TestMultiDimScore:
    """Tests for MultiDimScore model."""

    @pytest.fixture
    def sample_scores(self):
        """Sample dimension scores."""
        return (
            DimensionScore(
                dimension=ScoringDimension.CODEQL,
                score=0.9,
                confidence=0.8,
                available=True,
                evidence={},
            ),
            DimensionScore(
                dimension=ScoringDimension.REACHABILITY,
                score=0.7,
                confidence=0.7,
                available=True,
                evidence={},
            ),
            DimensionScore(
                dimension=ScoringDimension.TAINT_TRACKING,
                score=0.8,
                confidence=0.9,
                available=True,
                evidence={},
            ),
            DimensionScore(
                dimension=ScoringDimension.ATTACK_SURFACE,
                score=1.0,
                confidence=0.9,
                available=True,
                evidence={},
            ),
        )

    def test_create_multi_dim_score(self, sample_scores):
        """Test creating a multi-dim score."""
        score = MultiDimScore(
            codeql=sample_scores[0],
            reachability=sample_scores[1],
            taint_tracking=sample_scores[2],
            attack_surface=sample_scores[3],
            final_score=0.85,
            final_confidence=0.85,
            strategy_used="weighted_average",
            dimensions_used=["codeql", "reachability", "taint_tracking", "attack_surface"],
            exploitability_status=ExploitabilityStatus.EXPLOITABLE,
        )

        assert score.final_score == 0.85
        assert score.final_confidence == 0.85
        assert score.exploitability_status == ExploitabilityStatus.EXPLOITABLE
        assert len(score.dimensions_used) == 4
        assert len(score.missing_dimensions) == 0

    def test_multi_dim_score_to_dict(self, sample_scores):
        """Test MultiDimScore serialization."""
        score = MultiDimScore(
            codeql=sample_scores[0],
            reachability=sample_scores[1],
            taint_tracking=sample_scores[2],
            attack_surface=sample_scores[3],
            final_score=0.85,
            final_confidence=0.85,
            strategy_used="weighted_average",
        )

        result_dict = score.to_dict()

        assert isinstance(result_dict, dict)
        assert "dimensions" in result_dict
        assert "final_score" in result_dict
        assert "final_confidence" in result_dict
        assert "exploitability_status" in result_dict

    def test_get_dimension(self, sample_scores):
        """Test getting a specific dimension."""
        score = MultiDimScore(
            codeql=sample_scores[0],
            reachability=sample_scores[1],
            taint_tracking=sample_scores[2],
            attack_surface=sample_scores[3],
            final_score=0.85,
            final_confidence=0.85,
            strategy_used="weighted_average",
        )

        codeql_dim = score.get_dimension(ScoringDimension.CODEQL)
        assert codeql_dim.score == 0.9

        taint_dim = score.get_dimension(ScoringDimension.TAINT_TRACKING)
        assert taint_dim.score == 0.8


# ============================================================
# ScoringDimension Tests
# ============================================================

class TestScoringDimension:
    """Tests for ScoringDimension enum."""

    def test_dimension_values(self):
        """Test scoring dimension values."""
        assert ScoringDimension.CODEQL == "codeql"
        assert ScoringDimension.REACHABILITY == "reachability"
        assert ScoringDimension.TAINT_TRACKING == "taint_tracking"
        assert ScoringDimension.ATTACK_SURFACE == "attack_surface"
