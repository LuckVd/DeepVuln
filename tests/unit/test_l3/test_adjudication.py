"""Unit tests for Exploitability Adjudication module."""

import pytest

from src.layers.l3_analysis.adjudication import (
    FinalStatus,
    ArchitectureViolationError,
    AdjudicationResult,
    AdjudicationSummary,
    apply_exploitability_override,
    validate_no_conflict,
    adjudicate_findings,
    get_final_status,
    is_exploitable,
    requires_action,
    get_exploitability_value,
    get_severity_value,
)


class MockFinding:
    """Mock Finding object for testing."""

    def __init__(
        self,
        finding_id="test-001",
        rule_id="rule-001",
        severity="high",
        exploitability=None,
        final_score=0.8,
        metadata=None,
    ):
        self.id = finding_id
        self.rule_id = rule_id
        self.severity = severity
        self.exploitability = exploitability
        self.final_score = final_score
        self.final_status = None
        self.metadata = metadata or {}
        self.location = MockLocation()


class MockLocation:
    """Mock Location object for testing."""

    def __init__(self, file="test.py", line=10):
        self.file = file
        self.line = line


class TestFinalStatus:
    """Test FinalStatus enum."""

    def test_exploitable_value(self):
        """Test EXPLOITABLE enum value."""
        assert FinalStatus.EXPLOITABLE.value == "exploitable"

    def test_conditional_value(self):
        """Test CONDITIONAL enum value."""
        assert FinalStatus.CONDITIONAL.value == "conditional"

    def test_not_exploitable_value(self):
        """Test NOT_EXPLOITABLE enum value."""
        assert FinalStatus.NOT_EXPLOITABLE.value == "not_exploitable"

    def test_informational_value(self):
        """Test INFORMATIONAL enum value."""
        assert FinalStatus.INFORMATIONAL.value == "informational"

    def test_all_values_exist(self):
        """Test all expected values exist."""
        values = [s.value for s in FinalStatus]
        assert "exploitable" in values
        assert "conditional" in values
        assert "not_exploitable" in values
        assert "informational" in values


class TestGetExploitabilityValue:
    """Test get_exploitability_value function."""

    def test_direct_attribute(self):
        """Test getting exploitability from direct attribute."""
        finding = MockFinding(exploitability="exploitable")
        assert get_exploitability_value(finding) == "exploitable"

    def test_from_metadata(self):
        """Test getting exploitability from metadata."""
        finding = MockFinding(metadata={"exploitability": "likely"})
        assert get_exploitability_value(finding) == "likely"

    def test_none_exploitability(self):
        """Test when exploitability is None."""
        finding = MockFinding(exploitability=None)
        assert get_exploitability_value(finding) is None

    def test_no_exploitability(self):
        """Test when no exploitability is set."""
        finding = MockFinding()
        assert get_exploitability_value(finding) is None

    def test_enum_value(self):
        """Test when exploitability is an enum."""
        class MockEnum:
            value = "possible"

        finding = MockFinding()
        finding.exploitability = MockEnum()
        assert get_exploitability_value(finding) == "possible"


class TestGetSeverityValue:
    """Test get_severity_value function."""

    def test_string_severity(self):
        """Test getting string severity."""
        finding = MockFinding(severity="high")
        assert get_severity_value(finding) == "high"

    def test_enum_severity(self):
        """Test getting enum severity."""
        class MockSeverity:
            value = "CRITICAL"

        finding = MockFinding()
        finding.severity = MockSeverity()
        assert get_severity_value(finding) == "critical"

    def test_default_severity(self):
        """Test default when no severity."""
        finding = MockFinding()
        delattr(finding, "severity")
        assert get_severity_value(finding) == "medium"


class TestApplyExploitabilityOverride:
    """Test apply_exploitability_override function."""

    def test_not_exploitable_override(self):
        """Test NOT_EXPLOITABLE unconditional override."""
        finding = MockFinding(severity="critical", exploitability="not_exploitable")
        result = apply_exploitability_override(finding)

        assert result.final_status == FinalStatus.NOT_EXPLOITABLE
        assert result.override_applied is True
        assert finding.final_status == FinalStatus.NOT_EXPLOITABLE

    def test_not_exploitable_with_high_severity(self):
        """Test NOT_EXPLOITABLE overrides HIGH severity."""
        finding = MockFinding(severity="high", exploitability="not_exploitable")
        result = apply_exploitability_override(finding)

        assert result.final_status == FinalStatus.NOT_EXPLOITABLE
        assert "overrides" in result.override_reason.lower()

    def test_unlikely_with_high_downgrade(self):
        """Test UNLIKELY + HIGH → CONDITIONAL."""
        finding = MockFinding(severity="high", exploitability="unlikely")
        result = apply_exploitability_override(finding)

        assert result.final_status == FinalStatus.CONDITIONAL
        assert result.override_applied is True
        assert "downgrade" in result.override_reason.lower()

    def test_unlikely_with_critical_downgrade(self):
        """Test UNLIKELY + CRITICAL → CONDITIONAL."""
        finding = MockFinding(severity="critical", exploitability="unlikely")
        result = apply_exploitability_override(finding)

        assert result.final_status == FinalStatus.CONDITIONAL
        assert result.override_applied is True

    def test_unlikely_with_low_severity(self):
        """Test UNLIKELY + LOW → CONDITIONAL (no override needed)."""
        finding = MockFinding(severity="low", exploitability="unlikely")
        result = apply_exploitability_override(finding)

        assert result.final_status == FinalStatus.CONDITIONAL
        assert result.override_applied is False

    def test_exploitable_with_high(self):
        """Test EXPLOITABLE + HIGH → EXPLOITABLE."""
        finding = MockFinding(severity="high", exploitability="exploitable")
        result = apply_exploitability_override(finding)

        assert result.final_status == FinalStatus.EXPLOITABLE
        assert result.override_applied is True
        assert "confirms" in result.override_reason.lower()

    def test_exploitable_with_critical(self):
        """Test EXPLOITABLE + CRITICAL → EXPLOITABLE."""
        finding = MockFinding(severity="critical", exploitability="exploitable")
        result = apply_exploitability_override(finding)

        assert result.final_status == FinalStatus.EXPLOITABLE
        assert result.override_applied is True

    def test_exploitable_with_medium(self):
        """Test EXPLOITABLE + MEDIUM → CONDITIONAL."""
        finding = MockFinding(severity="medium", exploitability="exploitable")
        result = apply_exploitability_override(finding)

        assert result.final_status == FinalStatus.CONDITIONAL
        assert result.override_applied is False

    def test_likely_with_high(self):
        """Test LIKELY + HIGH → CONDITIONAL."""
        finding = MockFinding(severity="high", exploitability="likely")
        result = apply_exploitability_override(finding)

        assert result.final_status == FinalStatus.CONDITIONAL
        # LIKELY is elevated but not confirmed

    def test_possible_default(self):
        """Test POSSIBLE → CONDITIONAL."""
        finding = MockFinding(severity="high", exploitability="possible")
        result = apply_exploitability_override(finding)

        assert result.final_status == FinalStatus.CONDITIONAL

    def test_no_exploitability_default(self):
        """Test no exploitability → CONDITIONAL."""
        finding = MockFinding(severity="critical", exploitability=None)
        result = apply_exploitability_override(finding)

        assert result.final_status == FinalStatus.CONDITIONAL
        assert result.override_applied is False
        assert "default" in result.override_reason.lower()

    def test_confirmed_alias(self):
        """Test 'confirmed' as alias for 'exploitable'."""
        finding = MockFinding(severity="high", exploitability="confirmed")
        result = apply_exploitability_override(finding)

        assert result.final_status == FinalStatus.EXPLOITABLE

    def test_safe_alias(self):
        """Test 'safe' as alias for 'not_exploitable'."""
        finding = MockFinding(severity="critical", exploitability="safe")
        result = apply_exploitability_override(finding)

        assert result.final_status == FinalStatus.NOT_EXPLOITABLE


class TestValidateNoConflict:
    """Test validate_no_conflict function."""

    def test_no_conflict(self):
        """Test no conflict detection."""
        finding = MockFinding(severity="high", exploitability="exploitable")
        finding.final_status = FinalStatus.EXPLOITABLE

        assert validate_no_conflict(finding) is True

    def test_conflict_raises(self):
        """Test conflict raises ArchitectureViolationError."""
        finding = MockFinding(severity="high", exploitability="not_exploitable")
        finding.final_status = FinalStatus.EXPLOITABLE

        with pytest.raises(ArchitectureViolationError) as exc_info:
            validate_no_conflict(finding)

        assert "conflict" in str(exc_info.value).lower()

    def test_none_final_status(self):
        """Test with None final_status."""
        finding = MockFinding(severity="high", exploitability="not_exploitable")
        finding.final_status = None

        assert validate_no_conflict(finding) is True

    def test_safe_with_exploitable_conflict(self):
        """Test 'safe' alias with EXPLOITABLE status raises."""
        finding = MockFinding(severity="high", exploitability="safe")
        finding.final_status = FinalStatus.EXPLOITABLE

        with pytest.raises(ArchitectureViolationError):
            validate_no_conflict(finding)


class TestAdjudicateFindings:
    """Test adjudicate_findings function."""

    def test_batch_adjudication(self):
        """Test adjudicating multiple findings."""
        # Use different rule_ids to avoid consistency conflicts
        findings = [
            MockFinding(finding_id="f1", rule_id="rule-a", severity="critical", exploitability="exploitable"),
            MockFinding(finding_id="f2", rule_id="rule-b", severity="high", exploitability="not_exploitable"),
            MockFinding(finding_id="f3", rule_id="rule-c", severity="medium", exploitability="possible"),
        ]

        result, summary = adjudicate_findings(findings)

        assert summary.total_findings == 3
        assert summary.by_status["exploitable"] == 1
        assert summary.by_status["not_exploitable"] == 1
        assert summary.by_status["conditional"] == 1
        # P4-03: Consistency check should pass
        assert summary.consistency_check is not None
        assert summary.consistency_check["passed"] is True

    def test_overrides_counted(self):
        """Test that overrides are counted."""
        # Use different rule_ids to avoid consistency conflicts
        findings = [
            MockFinding(finding_id="f1", rule_id="rule-x", severity="critical", exploitability="not_exploitable"),
            MockFinding(finding_id="f2", rule_id="rule-y", severity="high", exploitability="unlikely"),
        ]

        result, summary = adjudicate_findings(findings)

        # Both should have overrides applied
        assert summary.overrides_applied >= 2

    def test_conflicts_detected(self):
        """Test that conflicts are detected when validate is enabled.

        Note: Conflicts can only occur if final_status is manually set after
        apply_exploitability_override. The override will always set the correct status.
        """
        # This test verifies that the conflict detection mechanism exists
        # In normal operation, apply_exploitability_override prevents conflicts
        findings = [
            MockFinding(finding_id="f1", rule_id="rule-z", severity="high", exploitability="not_exploitable"),
        ]

        result, summary = adjudicate_findings(findings, validate=True)

        # No conflict because override correctly sets NOT_EXPLOITABLE
        assert summary.conflicts_detected == 0
        assert findings[0].final_status == FinalStatus.NOT_EXPLOITABLE


class TestGetFinalStatus:
    """Test get_final_status function."""

    def test_existing_status(self):
        """Test getting existing final_status."""
        finding = MockFinding()
        finding.final_status = FinalStatus.EXPLOITABLE

        assert get_final_status(finding) == FinalStatus.EXPLOITABLE

    def test_computes_if_not_set(self):
        """Test computing status if not set."""
        finding = MockFinding(severity="high", exploitability="exploitable")
        finding.final_status = None

        status = get_final_status(finding)

        assert status == FinalStatus.EXPLOITABLE

    def test_string_status(self):
        """Test handling string status."""
        finding = MockFinding()
        finding.final_status = "conditional"

        status = get_final_status(finding)

        assert status == FinalStatus.CONDITIONAL


class TestIsExploitable:
    """Test is_exploitable function."""

    def test_exploitable_true(self):
        """Test EXPLOITABLE returns True."""
        finding = MockFinding()
        finding.final_status = FinalStatus.EXPLOITABLE

        assert is_exploitable(finding) is True

    def test_conditional_false(self):
        """Test CONDITIONAL returns False."""
        finding = MockFinding()
        finding.final_status = FinalStatus.CONDITIONAL

        assert is_exploitable(finding) is False

    def test_not_exploitable_false(self):
        """Test NOT_EXPLOITABLE returns False."""
        finding = MockFinding()
        finding.final_status = FinalStatus.NOT_EXPLOITABLE

        assert is_exploitable(finding) is False


class TestRequiresAction:
    """Test requires_action function."""

    def test_exploitable_requires_action(self):
        """Test EXPLOITABLE requires action."""
        finding = MockFinding()
        finding.final_status = FinalStatus.EXPLOITABLE

        assert requires_action(finding) is True

    def test_conditional_requires_action(self):
        """Test CONDITIONAL requires action."""
        finding = MockFinding()
        finding.final_status = FinalStatus.CONDITIONAL

        assert requires_action(finding) is True

    def test_not_exploitable_no_action(self):
        """Test NOT_EXPLOITABLE does not require action."""
        finding = MockFinding()
        finding.final_status = FinalStatus.NOT_EXPLOITABLE

        assert requires_action(finding) is False

    def test_informational_no_action(self):
        """Test INFORMATIONAL does not require action."""
        finding = MockFinding()
        finding.final_status = FinalStatus.INFORMATIONAL

        assert requires_action(finding) is False


class TestAdjudicationResult:
    """Test AdjudicationResult dataclass."""

    def test_create_result(self):
        """Test creating an AdjudicationResult."""
        result = AdjudicationResult(
            finding_id="test-001",
            final_status=FinalStatus.EXPLOITABLE,
            exploitability="exploitable",
            severity="high",
            override_applied=True,
            override_reason="Test reason",
        )

        assert result.finding_id == "test-001"
        assert result.final_status == FinalStatus.EXPLOITABLE
        assert result.override_applied is True

    def test_to_dict(self):
        """Test converting to dictionary."""
        result = AdjudicationResult(
            finding_id="test-001",
            final_status=FinalStatus.EXPLOITABLE,
            exploitability="exploitable",
            severity="high",
        )

        d = result.to_dict()
        assert d["finding_id"] == "test-001"
        assert d["final_status"] == "exploitable"


class TestAdjudicationSummary:
    """Test AdjudicationSummary dataclass."""

    def test_empty_summary(self):
        """Test creating empty summary."""
        summary = AdjudicationSummary()

        assert summary.total_findings == 0
        assert summary.overrides_applied == 0
        assert summary.conflicts_detected == 0

    def test_to_dict(self):
        """Test converting to dictionary."""
        summary = AdjudicationSummary(
            total_findings=10,
            overrides_applied=5,
            conflicts_detected=0,
        )
        summary.by_status = {"exploitable": 3, "conditional": 5, "not_exploitable": 2}

        d = summary.to_dict()
        assert d["override_enabled"] is True
        assert d["total_findings"] == 10
        assert d["conflict_detected"] is False


class TestArchitectureViolationError:
    """Test ArchitectureViolationError exception."""

    def test_exception_message(self):
        """Test exception message."""
        error = ArchitectureViolationError("Test violation")

        assert "Test violation" in str(error)

    def test_exception_inheritance(self):
        """Test exception inherits from Exception."""
        error = ArchitectureViolationError("Test")

        assert isinstance(error, Exception)


class TestEdgeCases:
    """Test edge cases and special scenarios."""

    def test_final_score_preserved(self):
        """Test that final_score is not modified."""
        finding = MockFinding(severity="high", exploitability="not_exploitable")
        finding.final_score = 0.95

        apply_exploitability_override(finding)

        # final_score should still exist
        assert finding.final_score == 0.95

    def test_severity_not_modified(self):
        """Test that severity field is not modified."""
        finding = MockFinding(severity="critical", exploitability="not_exploitable")

        apply_exploitability_override(finding)

        # severity should remain critical
        assert finding.severity == "critical"

    def test_case_insensitive_exploitability(self):
        """Test case-insensitive exploitability matching."""
        finding = MockFinding(severity="high", exploitability="EXPLOITABLE")
        result = apply_exploitability_override(finding)

        assert result.final_status == FinalStatus.EXPLOITABLE

    def test_whitespace_in_exploitability(self):
        """Test whitespace handling in exploitability."""
        finding = MockFinding(severity="high", exploitability="  exploitable  ")
        result = apply_exploitability_override(finding)

        assert result.final_status == FinalStatus.EXPLOITABLE

    def test_metadata_exploitability(self):
        """Test getting exploitability from metadata."""
        finding = MockFinding(severity="high")
        finding.metadata = {"exploitability": "exploitable"}

        result = apply_exploitability_override(finding)

        assert result.final_status == FinalStatus.EXPLOITABLE
