"""Regression tests for audit 2026-09 fix: a failed taint trace must not be
scored as an available 0.0 dimension.

``taint_tracker.trace_from_sink`` returns a TaintTraceResult with
``is_reachable=False, path=[], confidence=0.0`` when it could not analyze the
sink (no call-graph node and no source available). A genuine BFS
"not reachable" verdict always carries at least the sink node in ``path``.
Before the fix the failure was scored available=True/0.0, dragging the
weighted-average fusion score and confidence down even though the tracker
never ran on that sink.
"""

import pytest

from src.layers.l3_analysis.call_graph.models import TaintTraceResult
from src.layers.l3_analysis.scoring.models import ScoringDimension
from src.layers.l3_analysis.scoring.scorers.taint_scorer import TaintTrackingScorer


class TestTaintScorerAvailability:
    def test_no_result_unavailable(self):
        s = TaintTrackingScorer().score(None)
        assert s.available is False
        assert s.dimension == ScoringDimension.TAINT_TRACKING

    def test_failed_trace_is_unavailable(self):
        """Empty path + zero confidence = tracking could not analyze."""
        failed = TaintTraceResult(
            sink_id="x.py:foo",
            is_reachable=False,
            is_sanitized=False,
            confidence=0.0,
        )
        s = TaintTrackingScorer().score(failed)
        assert s.available is False
        assert s.score == 0.0

    def test_genuine_not_reachable_is_available(self):
        """A real BFS verdict carries the sink node in path."""
        genuine = TaintTraceResult(
            sink_id="n1",
            is_reachable=False,
            is_sanitized=False,
            path=["n1"],
            path_length=0,
            confidence=0.4,
        )
        s = TaintTrackingScorer().score(genuine)
        assert s.available is True
        assert s.score == 0.0

    def test_reachable_scores_high(self):
        reachable = TaintTraceResult(
            sink_id="n1",
            source_id="src",
            is_reachable=True,
            is_sanitized=False,
            path=["src", "n1"],
            path_length=1,
            confidence=0.8,
        )
        s = TaintTrackingScorer().score(reachable)
        assert s.available is True
        assert s.score > 0.9

    def test_sanitized_scores_low(self):
        sanitized = TaintTraceResult(
            sink_id="n1",
            source_id="src",
            is_reachable=True,
            is_sanitized=True,
            path=["src", "n1"],
            path_length=1,
            confidence=0.8,
        )
        s = TaintTrackingScorer().score(sanitized)
        assert s.available is True
        assert s.score < 0.3