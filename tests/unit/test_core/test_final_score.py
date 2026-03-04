"""Unit tests for Final Score Calculator module."""

import pytest

from src.core.final_score import (
    SEVERITY_WEIGHT,
    EXPLOITABILITY_WEIGHT,
    CONFIDENCE_WEIGHT,
    SEVERITY_SCORES,
    EXPLOITABILITY_SCORES,
    ENGINE_WEIGHTS,
    FinalScore,
    ExploitabilityLevel,
    get_severity_score,
    get_exploitability_score,
    get_confidence_score,
    get_engine_weight,
    calculate_final_score,
    calculate_finding_score,
    sort_findings_by_score,
    assign_scores_to_findings,
    get_score_weights,
    get_all_engine_weights,
    get_all_severity_scores,
    get_all_exploitability_scores,
)


class TestConstants:
    """Test module constants."""

    def test_severity_weight(self):
        """Test severity weight constant."""
        assert SEVERITY_WEIGHT == 0.4

    def test_exploitability_weight(self):
        """Test exploitability weight constant."""
        assert EXPLOITABILITY_WEIGHT == 0.4

    def test_confidence_weight(self):
        """Test confidence weight constant."""
        assert CONFIDENCE_WEIGHT == 0.2

    def test_weights_sum_to_one(self):
        """Test that weights sum to 1.0."""
        total = SEVERITY_WEIGHT + EXPLOITABILITY_WEIGHT + CONFIDENCE_WEIGHT
        assert total == 1.0

    def test_severity_scores_complete(self):
        """Test all severity levels have scores."""
        assert SEVERITY_SCORES["critical"] == 1.0
        assert SEVERITY_SCORES["high"] == 0.8
        assert SEVERITY_SCORES["medium"] == 0.6
        assert SEVERITY_SCORES["low"] == 0.4
        assert SEVERITY_SCORES["info"] == 0.2

    def test_exploitability_scores_complete(self):
        """Test all exploitability levels have scores."""
        assert EXPLOITABILITY_SCORES["exploitable"] == 1.0
        assert EXPLOITABILITY_SCORES["likely"] == 0.7
        assert EXPLOITABILITY_SCORES["possible"] == 0.5
        assert EXPLOITABILITY_SCORES["unlikely"] == 0.3
        assert EXPLOITABILITY_SCORES["not_exploitable"] == 0.0

    def test_engine_weights(self):
        """Test engine weight mapping."""
        assert ENGINE_WEIGHTS["opencode_agent"] == 1.2
        assert ENGINE_WEIGHTS["agent"] == 1.2
        assert ENGINE_WEIGHTS["codeql"] == 1.0
        assert ENGINE_WEIGHTS["semgrep"] == 0.8
        assert ENGINE_WEIGHTS["default"] == 1.0


class TestGetSeverityScore:
    """Test get_severity_score function."""

    def test_critical_severity(self):
        """Test CRITICAL severity score."""
        assert get_severity_score("critical") == 1.0

    def test_high_severity(self):
        """Test HIGH severity score."""
        assert get_severity_score("high") == 0.8

    def test_medium_severity(self):
        """Test MEDIUM severity score."""
        assert get_severity_score("medium") == 0.6

    def test_low_severity(self):
        """Test LOW severity score."""
        assert get_severity_score("low") == 0.4

    def test_info_severity(self):
        """Test INFO severity score."""
        assert get_severity_score("info") == 0.2

    def test_case_insensitive(self):
        """Test case-insensitive matching."""
        assert get_severity_score("CRITICAL") == 1.0
        assert get_severity_score("High") == 0.8
        assert get_severity_score("MEDIUM") == 0.6

    def test_unknown_severity(self):
        """Test unknown severity returns default."""
        assert get_severity_score("unknown") == 0.5

    def test_none_severity(self):
        """Test None severity returns default."""
        assert get_severity_score(None) == 0.5


class TestGetExploitabilityScore:
    """Test get_exploitability_score function."""

    def test_exploitable(self):
        """Test EXPLOITABLE score."""
        assert get_exploitability_score("exploitable") == 1.0

    def test_likely(self):
        """Test LIKELY score."""
        assert get_exploitability_score("likely") == 0.7

    def test_possible(self):
        """Test POSSIBLE score."""
        assert get_exploitability_score("possible") == 0.5

    def test_unlikely(self):
        """Test UNLIKELY score."""
        assert get_exploitability_score("unlikely") == 0.3

    def test_not_exploitable(self):
        """Test NOT_EXPLOITABLE score."""
        assert get_exploitability_score("not_exploitable") == 0.0

    def test_aliases(self):
        """Test alias values."""
        assert get_exploitability_score("confirmed") == 1.0
        assert get_exploitability_score("potential") == 0.5
        assert get_exploitability_score("safe") == 0.0

    def test_case_insensitive(self):
        """Test case-insensitive matching."""
        assert get_exploitability_score("EXPLOITABLE") == 1.0
        assert get_exploitability_score("Likely") == 0.7

    def test_unknown_exploitability(self):
        """Test unknown returns default."""
        assert get_exploitability_score("unknown") == 0.5

    def test_none_exploitability(self):
        """Test None returns default."""
        assert get_exploitability_score(None) == 0.5


class TestGetConfidenceScore:
    """Test get_confidence_score function."""

    def test_high_confidence(self):
        """Test high confidence (1.0)."""
        assert get_confidence_score(1.0) == 1.0

    def test_medium_confidence(self):
        """Test medium confidence (0.5)."""
        assert get_confidence_score(0.5) == 0.5

    def test_low_confidence(self):
        """Test low confidence (0.1)."""
        assert get_confidence_score(0.1) == 0.1

    def test_clamps_high(self):
        """Test clamping values above 1.0."""
        assert get_confidence_score(1.5) == 1.0

    def test_clamps_low(self):
        """Test clamping values below 0.0."""
        assert get_confidence_score(-0.5) == 0.0

    def test_none_confidence(self):
        """Test None returns default."""
        assert get_confidence_score(None) == 0.7


class TestGetEngineWeight:
    """Test get_engine_weight function."""

    def test_opencode_agent_weight(self):
        """Test opencode_agent engine weight."""
        assert get_engine_weight("opencode_agent") == 1.2

    def test_agent_weight(self):
        """Test agent engine weight."""
        assert get_engine_weight("agent") == 1.2

    def test_codeql_weight(self):
        """Test codeql engine weight."""
        assert get_engine_weight("codeql") == 1.0

    def test_semgrep_weight(self):
        """Test semgrep engine weight."""
        assert get_engine_weight("semgrep") == 0.8

    def test_unknown_engine(self):
        """Test unknown engine returns default."""
        assert get_engine_weight("unknown") == 1.0

    def test_none_engine(self):
        """Test None engine returns default."""
        assert get_engine_weight(None) == 1.0

    def test_case_insensitive(self):
        """Test case-insensitive matching."""
        assert get_engine_weight("SEMGREP") == 0.8
        assert get_engine_weight("CodeQL") == 1.0


class TestFinalScore:
    """Test FinalScore dataclass."""

    def test_create_final_score(self):
        """Test creating a FinalScore object."""
        score = FinalScore(
            total=0.8,
            severity_score=1.0,
            exploitability_score=0.7,
            confidence_score=0.9,
            engine_weight=1.2,
        )
        assert score.total == 0.8
        assert score.severity_score == 1.0
        assert score.exploitability_score == 0.7

    def test_to_dict(self):
        """Test converting to dictionary."""
        score = FinalScore(
            total=0.8,
            severity_score=1.0,
            exploitability_score=0.7,
            confidence_score=0.9,
            engine_weight=1.2,
        )
        d = score.to_dict()
        assert "total" in d
        assert "severity_score" in d
        assert "formula" in d

    def test_formula_generation(self):
        """Test formula string generation."""
        score = FinalScore(
            total=0.8,
            severity_score=1.0,
            exploitability_score=0.7,
            confidence_score=0.9,
            engine_weight=1.2,
        )
        assert "0.4" in score.formula  # SEVERITY_WEIGHT
        assert "0.4" in score.formula  # EXPLOITABILITY_WEIGHT
        assert "0.2" in score.formula  # CONFIDENCE_WEIGHT


class TestCalculateFinalScore:
    """Test calculate_final_score function."""

    def test_basic_calculation(self):
        """Test basic score calculation."""
        score = calculate_final_score(
            severity="critical",
            exploitability="exploitable",
            confidence=1.0,
            engine="codeql",
        )
        # (1.0 * 0.4 + 1.0 * 0.4 + 1.0 * 0.2) * 1.0 = 1.0
        assert score.total == 1.0
        assert score.severity_score == 1.0
        assert score.exploitability_score == 1.0
        assert score.confidence_score == 1.0
        assert score.engine_weight == 1.0

    def test_with_agent_weight(self):
        """Test score with agent engine weight."""
        score = calculate_final_score(
            severity="critical",
            exploitability="exploitable",
            confidence=1.0,
            engine="agent",
        )
        # (1.0 * 0.4 + 1.0 * 0.4 + 1.0 * 0.2) * 1.2 = 1.2
        assert score.total == 1.2

    def test_with_semgrep_weight(self):
        """Test score with semgrep engine weight."""
        score = calculate_final_score(
            severity="critical",
            exploitability="exploitable",
            confidence=1.0,
            engine="semgrep",
        )
        # (1.0 * 0.4 + 1.0 * 0.4 + 1.0 * 0.2) * 0.8 = 0.8
        assert score.total == 0.8

    def test_medium_values(self):
        """Test with medium severity and exploitability."""
        score = calculate_final_score(
            severity="medium",
            exploitability="possible",
            confidence=0.5,
            engine="codeql",
        )
        # (0.6 * 0.4 + 0.5 * 0.4 + 0.5 * 0.2) * 1.0 = 0.54
        assert 0.53 < score.total < 0.55

    def test_not_exploitable(self):
        """Test with not_exploitable exploitability."""
        score = calculate_final_score(
            severity="critical",
            exploitability="not_exploitable",
            confidence=1.0,
            engine="codeql",
        )
        # (1.0 * 0.4 + 0.0 * 0.4 + 1.0 * 0.2) * 1.0 = 0.6
        assert 0.599 < score.total < 0.601

    def test_with_pre_calculated_scores(self):
        """Test using pre-calculated scores."""
        score = calculate_final_score(
            severity_score=0.8,
            exploitability_score=0.7,
            confidence_score=0.9,
            engine_weight=1.2,
        )
        # (0.8 * 0.4 + 0.7 * 0.4 + 0.9 * 0.2) * 1.2 = 0.936
        assert 0.935 < score.total < 0.937


class TestCalculateFindingScore:
    """Test calculate_finding_score function."""

    def test_with_mock_finding(self):
        """Test with a mock finding object."""
        class MockFinding:
            severity = type("Severity", (), {"value": "high"})()
            confidence = 0.8
            source = "semgrep"

        score = calculate_finding_score(MockFinding())
        # (0.8 * 0.4 + 0.5 * 0.4 + 0.8 * 0.2) * 0.8 = 0.544
        assert 0.543 < score.total < 0.545

    def test_with_exploitability_in_metadata(self):
        """Test finding with exploitability in metadata."""
        class MockFinding:
            severity = type("Severity", (), {"value": "critical"})()
            confidence = 1.0
            source = "codeql"
            metadata = {"exploitability": "exploitable"}

        score = calculate_finding_score(MockFinding())
        # (1.0 * 0.4 + 1.0 * 0.4 + 1.0 * 0.2) * 1.0 = 1.0
        assert score.total == 1.0


class TestSortFindingsByScore:
    """Test sort_findings_by_score function."""

    def test_sort_descending(self):
        """Test sorting descending (highest first)."""
        class MockFinding:
            def __init__(self, score):
                self.final_score = score

        findings = [
            MockFinding(0.5),
            MockFinding(0.9),
            MockFinding(0.3),
            MockFinding(0.7),
        ]

        sorted_findings = sort_findings_by_score(findings)
        assert sorted_findings[0].final_score == 0.9
        assert sorted_findings[1].final_score == 0.7
        assert sorted_findings[2].final_score == 0.5
        assert sorted_findings[3].final_score == 0.3

    def test_sort_ascending(self):
        """Test sorting ascending (lowest first)."""
        class MockFinding:
            def __init__(self, score):
                self.final_score = score

        findings = [
            MockFinding(0.5),
            MockFinding(0.9),
            MockFinding(0.3),
        ]

        sorted_findings = sort_findings_by_score(findings, descending=False)
        assert sorted_findings[0].final_score == 0.3
        assert sorted_findings[1].final_score == 0.5
        assert sorted_findings[2].final_score == 0.9

    def test_handles_none_score(self):
        """Test handling None final_score."""
        class MockFinding:
            def __init__(self, score):
                self.final_score = score

        findings = [
            MockFinding(0.5),
            MockFinding(None),
            MockFinding(0.9),
        ]

        sorted_findings = sort_findings_by_score(findings)
        assert sorted_findings[0].final_score == 0.9
        assert sorted_findings[1].final_score == 0.5
        assert sorted_findings[2].final_score is None


class TestAssignScoresToFindings:
    """Test assign_scores_to_findings function."""

    def test_assigns_scores(self):
        """Test that scores are assigned to findings."""
        class MockFinding:
            severity = type("Severity", (), {"value": "high"})()
            confidence = 0.8
            source = "semgrep"
            final_score = None
            score_detail = None
            metadata = {}

        findings = [MockFinding(), MockFinding()]
        result = assign_scores_to_findings(findings)

        for finding in result:
            assert finding.final_score is not None
            assert finding.score_detail is not None
            assert "final_score" in finding.metadata

    def test_sorts_when_requested(self):
        """Test sorting when sort=True."""
        class MockFinding:
            def __init__(self, severity_value):
                self.severity = type("Severity", (), {"value": severity_value})()
                self.confidence = 0.8
                self.source = "codeql"
                self.final_score = None
                self.score_detail = None
                self.metadata = {}

        findings = [
            MockFinding("medium"),
            MockFinding("critical"),
            MockFinding("low"),
        ]

        result = assign_scores_to_findings(findings, sort=True)
        assert result[0].severity.value == "critical"
        assert result[2].severity.value == "low"


class TestConvenienceFunctions:
    """Test module-level convenience functions."""

    def test_get_score_weights(self):
        """Test get_score_weights function."""
        weights = get_score_weights()
        assert weights["severity"] == 0.4
        assert weights["exploitability"] == 0.4
        assert weights["confidence"] == 0.2

    def test_get_all_engine_weights(self):
        """Test get_all_engine_weights function."""
        weights = get_all_engine_weights()
        assert "agent" in weights
        assert "codeql" in weights
        assert "semgrep" in weights

    def test_get_all_severity_scores(self):
        """Test get_all_severity_scores function."""
        scores = get_all_severity_scores()
        assert "critical" in scores
        assert "high" in scores
        assert "medium" in scores

    def test_get_all_exploitability_scores(self):
        """Test get_all_exploitability_scores function."""
        scores = get_all_exploitability_scores()
        assert "exploitable" in scores
        assert "possible" in scores
        assert "not_exploitable" in scores


class TestExploitabilityLevel:
    """Test ExploitabilityLevel enum."""

    def test_enum_values(self):
        """Test enum values exist."""
        assert ExploitabilityLevel.EXPLOITABLE.value == "exploitable"
        assert ExploitabilityLevel.LIKELY.value == "likely"
        assert ExploitabilityLevel.POSSIBLE.value == "possible"
        assert ExploitabilityLevel.UNLIKELY.value == "unlikely"
        assert ExploitabilityLevel.NOT_EXPLOITABLE.value == "not_exploitable"
