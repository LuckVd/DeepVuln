"""
Tests for individual dimension scorers (P5-01d).

Tests CodeQL, Taint Tracking, Reachability, and Attack Surface scorers.
"""

import pytest

from src.layers.l3_analysis.call_graph.models import TaintTraceResult
from src.layers.l3_analysis.models import CodeLocation, Finding, SeverityLevel
from src.layers.l3_analysis.scoring.scorers.attack_surface_scorer import AttackSurfaceScorer
from src.layers.l3_analysis.scoring.scorers.codeql_scorer import CodeQLScorer
from src.layers.l3_analysis.scoring.scorers.reachability_scorer import ReachabilityScorer
from src.layers.l3_analysis.scoring.scorers.taint_scorer import TaintTrackingScorer
from src.layers.l3_analysis.task.context_builder import CallChainInfo

# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def sample_finding():
    """Sample vulnerability finding."""
    return Finding(
        id="test-001",
        rule_id="python.xss.user_input",
        title="XSS vulnerability",
        description="User input directly used in output",
        severity=SeverityLevel.HIGH,
        confidence=0.8,
        source="agent",
        source_path="/app/app.py",
        location=CodeLocation(
            file="app.py",
            line=10,
            end_line=12,
            function="vulnerable_handler",
            snippet="return f\"Hello {user_input}\"",
        ),
    )


# ============================================================
# CodeQLScorer Tests
# ============================================================

class TestCodeQLScorer:
    """Tests for CodeQLScorer."""

    def test_score_full_dataflow(self, sample_finding):
        """Test scoring with full dataflow (source + sink)."""
        scorer = CodeQLScorer()

        codeql_dataflow = {
            "has_source": True,
            "has_sink": True,
            "has_sanitizer": False,
            "path_length": 3,
        }

        score = scorer.score(sample_finding, codeql_dataflow)

        assert score.available is True
        assert score.score >= 0.7  # Full dataflow = high score (with path length factor)
        assert score.confidence > 0.5

    def test_score_with_sanitizer(self, sample_finding):
        """Test scoring with sanitizer in path."""
        scorer = CodeQLScorer()

        codeql_dataflow = {
            "has_source": True,
            "has_sink": True,
            "has_sanitizer": True,
            "sanitizer_effectiveness": "full",
            "path_length": 2,
        }

        score = scorer.score(sample_finding, codeql_dataflow)

        assert score.available is True
        assert score.score == 0.0  # Full sanitizer = not exploitable

    def test_score_no_dataflow(self, sample_finding):
        """Test scoring without CodeQL data."""
        scorer = CodeQLScorer()

        score = scorer.score(sample_finding, None)

        assert score.available is False
        assert score.score == 0.1
        assert score.confidence == 0.2


# ============================================================
# TaintTrackingScorer Tests
# ============================================================

class TestTaintTrackingScorer:
    """Tests for TaintTrackingScorer."""

    def test_score_exploitable(self):
        """Test scoring exploitable vulnerability."""
        scorer = TaintTrackingScorer()

        taint_result = TaintTraceResult(
            sink_id="test:app.py:vulnerable",
            is_reachable=True,
            is_sanitized=False,
            path_length=1,  # Short path = highest score
            confidence=0.9,
        )

        score = scorer.score(taint_result)

        assert score.available is True
        assert score.score >= 0.9  # Exploitable with short path = high score
        assert score.confidence > 0.8

    def test_score_sanitized(self):
        """Test scoring sanitized vulnerability."""
        scorer = TaintTrackingScorer()

        taint_result = TaintTraceResult(
            sink_id="test:app.py:vulnerable",
            is_reachable=True,
            is_sanitized=True,
            path_length=2,
            confidence=0.9,
        )

        score = scorer.score(taint_result)

        assert score.available is True
        assert score.score <= 0.2  # Sanitized = low score

    def test_score_not_reachable(self):
        """Test scoring unreachable vulnerability."""
        scorer = TaintTrackingScorer()

        taint_result = TaintTraceResult(
            sink_id="test:app.py:vulnerable",
            is_reachable=False,
            is_sanitized=False,
            path_length=0,
            confidence=0.5,
        )

        score = scorer.score(taint_result)

        assert score.available is True
        assert score.score == 0.0  # Not reachable = not exploitable

    def test_score_no_result(self):
        """Test scoring without taint tracking result."""
        scorer = TaintTrackingScorer()

        score = scorer.score(None)

        assert score.available is False
        assert score.score == 0.0


# ============================================================
# ReachabilityScorer Tests
# ============================================================

class TestReachabilityScorer:
    """Tests for ReachabilityScorer."""

    def test_score_http_entry_point(self):
        """Test scoring with HTTP entry point."""
        scorer = ReachabilityScorer()

        call_chain = CallChainInfo(
            function_name="handler",
            file_path="app.py",
            callers=[],
            is_entry_point=True,
            entry_point_type="HTTP",
        )

        score = scorer.score(call_chain)

        assert score.available is True
        assert score.score == 1.0  # HTTP = highest score
        assert score.confidence == 0.95

    def test_score_cli_entry_point(self):
        """Test scoring with CLI entry point."""
        scorer = ReachabilityScorer()

        call_chain = CallChainInfo(
            function_name="main",
            file_path="cli.py",
            callers=[],
            is_entry_point=True,
            entry_point_type="CLI",
        )

        score = scorer.score(call_chain)

        assert score.available is True
        assert score.score == 0.8  # CLI = medium-high score
        assert score.confidence == 0.85

    def test_score_with_callers(self):
        """Test scoring function with callers (indirect entry)."""
        scorer = ReachabilityScorer()

        call_chain = CallChainInfo(
            function_name="helper",
            file_path="utils.py",
            callers=["caller1", "caller2"],
            is_entry_point=False,
            entry_point_type=None,
        )

        score = scorer.score(call_chain)

        assert score.available is True
        assert 0.3 <= score.score <= 0.5  # Has callers = medium score

    def test_score_isolated(self):
        """Test scoring isolated function (no callers)."""
        scorer = ReachabilityScorer()

        call_chain = CallChainInfo(
            function_name="isolated",
            file_path="isolated.py",
            callers=[],
            is_entry_point=False,
            entry_point_type=None,
        )

        score = scorer.score(call_chain)

        assert score.available is True
        assert score.score == 0.1  # Isolated = low score

    def test_score_no_call_chain(self):
        """Test scoring without call chain info."""
        scorer = ReachabilityScorer()

        score = scorer.score(None)

        assert score.available is False
        assert score.score == 0.2


# ============================================================
# AttackSurfaceScorer Tests
# ============================================================

class TestAttackSurfaceScorer:
    """Tests for AttackSurfaceScorer."""

    def test_score_http_entry(self):
        """Test scoring HTTP entry point."""
        scorer = AttackSurfaceScorer()

        score = scorer.score("HTTP")

        assert score.available is True
        assert score.score == 1.0
        assert score.confidence == 0.9

    def test_score_cli_entry(self):
        """Test scoring CLI entry point."""
        scorer = AttackSurfaceScorer()

        score = scorer.score("CLI")

        assert score.available is True
        assert score.score == 0.7
        assert score.confidence == 0.9

    def test_score_unknown_type(self):
        """Test scoring unknown entry point type."""
        scorer = AttackSurfaceScorer()

        score = scorer.score("UNKNOWN")

        assert score.available is True
        assert score.score == 0.5
        assert score.confidence == 0.5

    def test_score_library_function(self):
        """Test scoring library function."""
        scorer = AttackSurfaceScorer()

        score = scorer.score("LIBRARY")

        assert score.available is True
        assert score.score == 0.3  # Library = lower score

    def test_score_no_entry_type(self):
        """Test scoring without entry point type."""
        scorer = AttackSurfaceScorer()

        score = scorer.score(None)

        assert score.available is False
        assert score.score == 0.5
