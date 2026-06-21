"""Phase 18/P6 — evidence gate tests for MultiDimScorer.

Verifies the evidence gate reads each dimension's evidence *conclusion*
(confirming vs supporting), not merely whether the dimension ran (``available``).
A finding is EXPLOITABLE only with a dataflow-confirming dimension (CodeQL full
source->sink, or taint is_exploitable); supporting-only evidence (reachability
/ taint reachable-but-not-exploitable) downgrades to CONDITIONAL.
"""

from src.layers.l3_analysis.rounds.round_four import ExploitabilityStatus
from src.layers.l3_analysis.scoring.models import (
    DimensionScore,
    MultiDimConfig,
    MultiDimScore,
    ScoringDimension,
)
from src.layers.l3_analysis.scoring.multi_dim_scorer import MultiDimScorer


def _dim(dimension, available, evidence=None, score=0.5, confidence=0.8):
    return DimensionScore(
        dimension=dimension,
        score=score,
        confidence=confidence,
        available=available,
        evidence=evidence or {},
    )


def _scorer():
    return MultiDimScorer(config=MultiDimConfig())


class TestEvidenceGate:
    """Tests for the confirming/supporting evidence gate in _derive_status."""

    def test_codeql_full_dataflow_is_exploitable(self):
        dims = [
            _dim(
                ScoringDimension.CODEQL.value,
                True,
                {"has_source": True, "has_sink": True, "has_sanitizer": False},
            ),
            _dim(ScoringDimension.REACHABILITY.value, False),
            _dim(ScoringDimension.TAINT_TRACKING.value, False),
            _dim(ScoringDimension.ATTACK_SURFACE.value, True),
        ]
        status, confirming, _ = _scorer()._derive_status(0.8, 0.8, dims)
        assert status == ExploitabilityStatus.EXPLOITABLE
        assert confirming == 1

    def test_taint_exploitable_confirms_without_codeql(self):
        # No CodeQL on this machine — taint (AST/tree-sitter) is the dataflow
        # source. A real exploitable finding is still confirmed.
        dims = [
            _dim(ScoringDimension.CODEQL.value, False),
            _dim(ScoringDimension.REACHABILITY.value, True, {"is_reachable": True}),
            _dim(
                ScoringDimension.TAINT_TRACKING.value,
                True,
                {
                    "is_exploitable": True,
                    "is_reachable": True,
                    "is_sanitized": False,
                },
            ),
            _dim(ScoringDimension.ATTACK_SURFACE.value, True),
        ]
        status, confirming, supporting = _scorer()._derive_status(0.8, 0.8, dims)
        assert status == ExploitabilityStatus.EXPLOITABLE
        assert confirming == 1  # taint
        assert supporting == 1  # reachability

    def test_supporting_only_taint_is_conditional(self):
        dims = [
            _dim(ScoringDimension.CODEQL.value, False),
            _dim(
                ScoringDimension.TAINT_TRACKING.value,
                True,
                {
                    "is_exploitable": False,
                    "is_reachable": True,
                    "is_sanitized": False,
                },
            ),
            _dim(ScoringDimension.ATTACK_SURFACE.value, True),
        ]
        status, confirming, supporting = _scorer()._derive_status(0.8, 0.8, dims)
        assert status == ExploitabilityStatus.CONDITIONAL
        assert confirming == 0
        assert supporting == 1

    def test_supporting_only_reachability_is_conditional(self):
        dims = [
            _dim(ScoringDimension.CODEQL.value, False),
            _dim(ScoringDimension.TAINT_TRACKING.value, False),
            _dim(ScoringDimension.REACHABILITY.value, True, {"is_reachable": True}),
            _dim(ScoringDimension.ATTACK_SURFACE.value, True),
        ]
        status, confirming, _ = _scorer()._derive_status(0.8, 0.8, dims)
        assert status == ExploitabilityStatus.CONDITIONAL
        assert confirming == 0

    def test_attack_surface_only_is_needs_review(self):
        dims = [
            _dim(ScoringDimension.CODEQL.value, False),
            _dim(ScoringDimension.REACHABILITY.value, False),
            _dim(ScoringDimension.TAINT_TRACKING.value, False),
            _dim(ScoringDimension.ATTACK_SURFACE.value, True),
        ]
        status, confirming, supporting = _scorer()._derive_status(0.8, 0.8, dims)
        assert status == ExploitabilityStatus.NEEDS_REVIEW
        assert confirming == 0
        assert supporting == 0

    def test_codeql_sanitizer_blocks_confirming(self):
        # Full source+sink but a sanitizer on path -> not confirming.
        dims = [
            _dim(
                ScoringDimension.CODEQL.value,
                True,
                {"has_source": True, "has_sink": True, "has_sanitizer": True},
            ),
            _dim(ScoringDimension.TAINT_TRACKING.value, False),
            _dim(ScoringDimension.REACHABILITY.value, False),
            _dim(ScoringDimension.ATTACK_SURFACE.value, True),
        ]
        status, confirming, _ = _scorer()._derive_status(0.8, 0.8, dims)
        assert confirming == 0
        assert status == ExploitabilityStatus.NEEDS_REVIEW

    def test_low_confidence_is_needs_review(self):
        dims = [
            _dim(
                ScoringDimension.CODEQL.value,
                True,
                {"has_source": True, "has_sink": True, "has_sanitizer": False},
            ),
        ]
        status, _, _ = _scorer()._derive_status(0.9, 0.1, dims)
        assert status == ExploitabilityStatus.NEEDS_REVIEW

    def test_counts_exposed_in_multidimscore_to_dict(self):
        ms = MultiDimScore(
            codeql=_dim(
                ScoringDimension.CODEQL.value,
                True,
                {"has_source": True, "has_sink": True, "has_sanitizer": False},
            ),
            reachability=_dim(ScoringDimension.REACHABILITY.value, False),
            taint_tracking=_dim(ScoringDimension.TAINT_TRACKING.value, False),
            attack_surface=_dim(ScoringDimension.ATTACK_SURFACE.value, True),
            final_score=0.8,
            final_confidence=0.8,
            strategy_used="weighted_average",
            confirming_evidence_count=1,
            supporting_evidence_count=0,
        )
        d = ms.to_dict()
        assert d["confirming_evidence_count"] == 1
        assert d["supporting_evidence_count"] == 0
