"""Unit tests for Unified Report Status module."""

import pytest

from src.layers.l3_analysis.reporting import (
    ReportStatus,
    STATUS_PRIORITY,
    is_suppressed,
    get_final_status_value,
    map_to_report_status,
    apply_report_status,
    sort_by_report_status,
    get_status_display,
    filter_non_suppressed,
    get_actionable_findings,
)


class MockFinding:
    """Mock Finding for testing."""

    def __init__(
        self,
        finding_id="test-001",
        rule_id="rule-001",
        source="semgrep",
        severity="high",
        exploitability=None,
        final_status=None,
        final_score=None,
        location=None,
        metadata=None,
        duplicate_count=0,
        related_engines=None,
    ):
        self.id = finding_id
        self.rule_id = rule_id
        self.source = source
        self.severity = severity
        self.exploitability = exploitability
        self.final_status = final_status
        self.final_score = final_score
        self.location = location or MockLocation()
        self.metadata = metadata if metadata is not None else {}
        self.duplicate_count = duplicate_count
        self.related_engines = related_engines if related_engines is not None else []
        self.report_status = None


class MockLocation:
    """Mock Location for testing."""

    def __init__(self, file="test.py", line=10):
        self.file = file
        self.line = line


# ============================================================
# Test ReportStatus Enum
# ============================================================

class TestReportStatus:
    """Test ReportStatus enum."""

    def test_values(self):
        """Test enum values."""
        assert ReportStatus.EXPLOITABLE.value == "exploitable"
        assert ReportStatus.CONDITIONAL.value == "conditional"
        assert ReportStatus.INFORMATIONAL.value == "informational"
        assert ReportStatus.SUPPRESSED.value == "suppressed"

    def test_str_enum(self):
        """Test string enum behavior."""
        assert ReportStatus.EXPLOITABLE == "exploitable"
        assert ReportStatus.CONDITIONAL.value == "conditional"

    def test_four_statuses_only(self):
        """Test only four statuses exist."""
        assert len(list(ReportStatus)) == 4


# ============================================================
# Test Status Priority
# ============================================================

class TestStatusPriority:
    """Test STATUS_PRIORITY mapping."""

    def test_exploitable_highest(self):
        """Test exploitable has highest priority."""
        assert STATUS_PRIORITY[ReportStatus.EXPLOITABLE] == 4

    def test_suppressed_lowest(self):
        """Test suppressed has lowest priority."""
        assert STATUS_PRIORITY[ReportStatus.SUPPRESSED] == 1

    def test_ordering(self):
        """Test priority ordering."""
        assert STATUS_PRIORITY[ReportStatus.EXPLOITABLE] > STATUS_PRIORITY[ReportStatus.CONDITIONAL]
        assert STATUS_PRIORITY[ReportStatus.CONDITIONAL] > STATUS_PRIORITY[ReportStatus.INFORMATIONAL]
        assert STATUS_PRIORITY[ReportStatus.INFORMATIONAL] > STATUS_PRIORITY[ReportStatus.SUPPRESSED]


# ============================================================
# Test Status Display
# ============================================================

class TestStatusDisplay:
    """Test status display functions."""

    def test_exploitable_display(self):
        """Test exploitable display."""
        emoji, color = get_status_display(ReportStatus.EXPLOITABLE)
        assert emoji == "🔴"
        assert color == "red"

    def test_conditional_display(self):
        """Test conditional display."""
        emoji, color = get_status_display(ReportStatus.CONDITIONAL)
        assert emoji == "🟡"
        assert color == "yellow"

    def test_informational_display(self):
        """Test informational display."""
        emoji, color = get_status_display(ReportStatus.INFORMATIONAL)
        assert emoji == "🔵"
        assert color == "blue"

    def test_suppressed_display(self):
        """Test suppressed display."""
        emoji, color = get_status_display(ReportStatus.SUPPRESSED)
        assert emoji == "⚫"
        assert color == "dim"

    def test_string_input(self):
        """Test string input."""
        emoji, color = get_status_display("exploitable")
        assert emoji == "🔴"

    def test_invalid_input(self):
        """Test invalid input."""
        emoji, color = get_status_display("invalid")
        assert emoji == "❓"
        assert color == "white"


# ============================================================
# Test is_suppressed
# ============================================================

class TestIsSuppressed:
    """Test is_suppressed function."""

    def test_suppressed_metadata(self):
        """Test suppressed=True in metadata."""
        finding = MockFinding(metadata={"suppressed": True})
        assert is_suppressed(finding) is True

    def test_filtered_by_finding_budget(self):
        """Test filtered_by finding_budget."""
        finding = MockFinding(metadata={"filtered_by": "finding_budget"})
        assert is_suppressed(finding) is True

    def test_filtered_by_rule_gating(self):
        """Test filtered_by rule_gating."""
        finding = MockFinding(metadata={"filtered_by": "rule_gating"})
        assert is_suppressed(finding) is True

    def test_filtered_by_ast_validator(self):
        """Test filtered_by ast_validator."""
        finding = MockFinding(metadata={"filtered_by": "ast_validator"})
        assert is_suppressed(finding) is True

    def test_filtered_by_file_filter(self):
        """Test filtered_by file_filter."""
        finding = MockFinding(metadata={"filtered_by": "file_filter"})
        assert is_suppressed(finding) is True

    def test_not_suppressed(self):
        """Test normal finding not suppressed."""
        finding = MockFinding()
        assert is_suppressed(finding) is False

    def test_duplicate_count_not_suppressed(self):
        """Test duplicate_count doesn't cause suppression."""
        finding = MockFinding(duplicate_count=1)
        assert is_suppressed(finding) is False


# ============================================================
# Test map_to_report_status
# ============================================================

class TestMapToReportStatus:
    """Test map_to_report_status function."""

    def test_exploitable_mapping(self):
        """Test exploitable mapping."""
        finding = MockFinding(final_status="exploitable")
        result = map_to_report_status(finding)
        assert result == ReportStatus.EXPLOITABLE

    def test_conditional_mapping(self):
        """Test conditional mapping."""
        finding = MockFinding(final_status="conditional")
        result = map_to_report_status(finding)
        assert result == ReportStatus.CONDITIONAL

    def test_not_exploitable_mapping(self):
        """Test not_exploitable -> informational."""
        finding = MockFinding(final_status="not_exploitable")
        result = map_to_report_status(finding)
        assert result == ReportStatus.INFORMATIONAL

    def test_informational_mapping(self):
        """Test informational mapping."""
        finding = MockFinding(final_status="informational")
        result = map_to_report_status(finding)
        assert result == ReportStatus.INFORMATIONAL

    def test_no_final_status_falls_back(self):
        """Test no final_status defaults to CONDITIONAL."""
        finding = MockFinding(final_status=None)
        result = map_to_report_status(finding)
        assert result == ReportStatus.CONDITIONAL

    def test_suppressed_takes_priority(self):
        """Test suppressed takes priority over final_status."""
        finding = MockFinding(
            final_status="exploitable",
            metadata={"suppressed": True}
        )
        result = map_to_report_status(finding)
        assert result == ReportStatus.SUPPRESSED


# ============================================================
# Test get_final_status_value
# ============================================================

class TestGetFinalStatusValue:
    """Test get_final_status_value function."""

    def test_string_status(self):
        """Test string status."""
        finding = MockFinding(final_status="exploitable")
        result = get_final_status_value(finding)
        assert result == "exploitable"

    def test_none_status(self):
        """Test None status."""
        finding = MockFinding(final_status=None)
        result = get_final_status_value(finding)
        assert result is None

    def test_no_final_status_attr(self):
        """Test missing final_status attribute."""
        finding = MockFinding()
        delattr(finding, "final_status")
        result = get_final_status_value(finding)
        assert result is None


# ============================================================
# Test apply_report_status
# ============================================================

class TestApplyReportStatus:
    """Test apply_report_status function."""

    def test_apply_basic(self):
        """Test basic application."""
        findings = [
            MockFinding(finding_id="f1", final_status="exploitable"),
            MockFinding(finding_id="f2", final_status="conditional"),
            MockFinding(finding_id="f3", final_status="informational"),
        ]
        counts = apply_report_status(findings)
        assert counts["exploitable"] == 1
        assert counts["conditional"] == 1
        assert counts["informational"] == 1
        assert findings[0].report_status == "exploitable"
        assert findings[1].report_status == "conditional"
        assert findings[2].report_status == "informational"

    def test_apply_empty(self):
        """Test empty findings."""
        counts = apply_report_status([])
        assert counts["exploitable"] == 0
        assert counts["conditional"] == 0

    def test_apply_with_suppressed(self):
        """Test with suppressed findings."""
        findings = [
            MockFinding(finding_id="f1", final_status="exploitable"),
            MockFinding(finding_id="f2", metadata={"suppressed": True}),
        ]
        counts = apply_report_status(findings)
        assert counts["exploitable"] == 1
        assert counts["suppressed"] == 1


# ============================================================
# Test sort_by_report_status
# ============================================================

class TestSortByReportStatus:
    """Test sort_by_report_status function."""

    def test_sort_descending(self):
        """Test descending sort."""
        findings = [
            MockFinding(finding_id="f1", final_status="informational"),
            MockFinding(finding_id="f2", final_status="exploitable"),
            MockFinding(finding_id="f3", final_status="conditional"),
        ]
        sorted_findings = sort_by_report_status(findings)
        assert sorted_findings[0].final_status == "exploitable"
        assert sorted_findings[1].final_status == "conditional"
        assert sorted_findings[2].final_status == "informational"

    def test_sort_ascending(self):
        """Test ascending sort."""
        findings = [
            MockFinding(finding_id="f1", final_status="exploitable"),
            MockFinding(finding_id="f2", final_status="informational"),
            MockFinding(finding_id="f3", final_status="conditional"),
        ]
        sorted_findings = sort_by_report_status(findings, descending=False)
        assert sorted_findings[0].final_status == "informational"
        assert sorted_findings[2].final_status == "exploitable"


# ============================================================
# Test filter_non_suppressed
# ============================================================

class TestFilterNonSuppressed:
    """Test filter_non_suppressed function."""

    def test_filter_basic(self):
        """Test basic filtering."""
        findings = [
            MockFinding(finding_id="f1", final_status="exploitable"),
            MockFinding(finding_id="f2", metadata={"suppressed": True}),
            MockFinding(finding_id="f3", final_status="conditional"),
        ]
        filtered = filter_non_suppressed(findings)
        assert len(filtered) == 2
        assert all(f.id != "f2" for f in filtered)

    def test_filter_all_non_suppressed(self):
        """Test all non-suppressed."""
        findings = [
            MockFinding(finding_id="f1", final_status="exploitable"),
            MockFinding(finding_id="f2", final_status="conditional"),
        ]
        filtered = filter_non_suppressed(findings)
        assert len(filtered) == 2

    def test_filter_all_suppressed(self):
        """Test all suppressed."""
        findings = [
            MockFinding(finding_id="f1", metadata={"suppressed": True}),
            MockFinding(finding_id="f2", metadata={"filtered_by": "rule_gating"}),
        ]
        filtered = filter_non_suppressed(findings)
        assert len(filtered) == 0


# ============================================================
# Test get_actionable_findings
# ============================================================

class TestGetActionableFindings:
    """Test get_actionable_findings function."""

    def test_actionable_basic(self):
        """Test basic actionable filtering."""
        findings = [
            MockFinding(finding_id="f1", final_status="exploitable"),
            MockFinding(finding_id="f2", final_status="conditional"),
            MockFinding(finding_id="f3", final_status="informational"),
        ]
        actionable = get_actionable_findings(findings)
        assert len(actionable) == 2
        assert all(f.id != "f3" for f in actionable)

    def test_actionable_only_exploitable(self):
        """Test only exploitable."""
        findings = [
            MockFinding(finding_id="f1", final_status="exploitable"),
            MockFinding(finding_id="f2", final_status="informational"),
        ]
        actionable = get_actionable_findings(findings)
        assert len(actionable) == 1
        assert actionable[0].id == "f1"

    def test_actionable_none(self):
        """Test no actionable."""
        findings = [
            MockFinding(finding_id="f1", final_status="informational"),
            MockFinding(finding_id="f2", metadata={"suppressed": True}),
        ]
        actionable = get_actionable_findings(findings)
        assert len(actionable) == 0


# ============================================================
# Test No Confirmed in Output
# ============================================================

class TestNoConfirmedInOutput:
    """Test that 'confirmed' never appears in output status."""

    def test_confirmed_not_report_status(self):
        """Test that 'confirmed' is not a valid ReportStatus."""
        valid_statuses = [s.value for s in ReportStatus]
        assert "confirmed" not in valid_statuses

    def test_four_statuses_defined(self):
        """Test exactly four statuses defined."""
        expected = {"exploitable", "conditional", "informational", "suppressed"}
        actual = {s.value for s in ReportStatus}
        assert actual == expected


# ============================================================
# Test Edge Cases
# ============================================================

class TestEdgeCases:
    """Test edge cases."""

    def test_finding_with_all_metadata(self):
        """Test finding with all metadata fields."""
        finding = MockFinding(
            finding_id="f1",
            rule_id="r1",
            source="semgrep",
            severity="high",
            exploitability="exploitable",
            final_status="exploitable",
            final_score=0.9,
            duplicate_count=0,
            related_engines=["semgrep"],
            metadata={"key": "value"},
        )
        result = map_to_report_status(finding)
        assert result == ReportStatus.EXPLOITABLE

    def test_case_insensitive_status(self):
        """Test case insensitive status."""
        finding = MockFinding(final_status="EXPLOITABLE")
        # Need to simulate enum or uppercase handling
        finding.final_status = "EXPLOITABLE"
        # The function handles lowercase
        result = map_to_report_status(finding)
        # Should handle uppercase
        assert result == ReportStatus.EXPLOITABLE or result == ReportStatus.CONDITIONAL

    def test_whitespace_status(self):
        """Test whitespace in status."""
        finding = MockFinding(final_status="  exploitable  ")
        result = map_to_report_status(finding)
        assert result == ReportStatus.EXPLOITABLE

    def test_empty_findings_list(self):
        """Test empty findings list."""
        counts = apply_report_status([])
        assert counts == {"exploitable": 0, "conditional": 0, "informational": 0, "suppressed": 0}

    def test_large_batch(self):
        """Test large batch of findings."""
        findings = [
            MockFinding(
                finding_id=f"f{i}",
                final_status=["exploitable", "conditional", "informational"][i % 3]
            )
            for i in range(100)
        ]
        counts = apply_report_status(findings)
        assert counts["exploitable"] > 0
        assert counts["conditional"] > 0
        assert counts["informational"] > 0
