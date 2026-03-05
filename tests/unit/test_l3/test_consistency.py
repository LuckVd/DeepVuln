"""Unit tests for Global Adjudication Consistency module."""

import pytest

from src.layers.l3_analysis.consistency import (
    SEVERITY_LEVELS,
    STATUS_LEVELS,
    AdjudicationConsistencyChecker,
    ConflictInfo,
    ConsistencyCheckResult,
    GlobalAdjudicationError,
    SeverityLevel,
    StatusLevel,
    generate_logical_vuln_id,
    validate_consistency,
)


class MockFinding:
    """Mock Finding object for testing."""

    def __init__(
        self,
        finding_id="test-001",
        rule_id="rule-001",
        source="semgrep",
        exploitability=None,
        final_status=None,
        severity=None,
        location=None,
        metadata=None,
        logical_vuln_id=None,
    ):
        self.id = finding_id
        self.rule_id = rule_id
        self.source = source
        self.exploitability = exploitability
        self.final_status = final_status
        self.severity = severity
        self.logical_vuln_id = logical_vuln_id
        self.location = location or MockLocation()
        self.metadata = metadata or {}


class MockLocation:
    """Mock Location object for testing."""

    def __init__(self, file="test.py", line=10):
        self.file = file
        self.line = line


class TestStatusLevel:
    """Test StatusLevel enum."""

    def test_not_exploitable_level(self):
        """Test NOT_EXPLOITABLE is lowest."""
        assert StatusLevel.NOT_EXPLOITABLE == 0

    def test_exploitable_level(self):
        """Test EXPLOITABLE is highest."""
        assert StatusLevel.EXPLOITABLE == 3

    def test_level_ordering(self):
        """Test status levels are ordered correctly."""
        assert StatusLevel.NOT_EXPLOITABLE < StatusLevel.INFORMATIONAL
        assert StatusLevel.INFORMATIONAL < StatusLevel.CONDITIONAL
        assert StatusLevel.CONDITIONAL < StatusLevel.EXPLOITABLE

    def test_status_levels_dict(self):
        """Test STATUS_LEVELS mapping."""
        assert STATUS_LEVELS["not_exploitable"] == 0
        assert STATUS_LEVELS["exploitable"] == 3
        assert STATUS_LEVELS["conditional"] == 2


class TestSeverityLevel:
    """Test SeverityLevel enum."""

    def test_info_level(self):
        """Test INFO is lowest."""
        assert SeverityLevel.INFO == 0

    def test_critical_level(self):
        """Test CRITICAL is highest."""
        assert SeverityLevel.CRITICAL == 4

    def test_level_ordering(self):
        """Test severity levels are ordered correctly."""
        assert SeverityLevel.INFO < SeverityLevel.LOW
        assert SeverityLevel.LOW < SeverityLevel.MEDIUM
        assert SeverityLevel.MEDIUM < SeverityLevel.HIGH
        assert SeverityLevel.HIGH < SeverityLevel.CRITICAL

    def test_severity_levels_dict(self):
        """Test SEVERITY_LEVELS mapping."""
        assert SEVERITY_LEVELS["info"] == 0
        assert SEVERITY_LEVELS["low"] == 1
        assert SEVERITY_LEVELS["medium"] == 2
        assert SEVERITY_LEVELS["high"] == 3
        assert SEVERITY_LEVELS["critical"] == 4


class TestGlobalAdjudicationError:
    """Test GlobalAdjudicationError exception."""

    def test_create_error(self):
        """Test creating error."""
        error = GlobalAdjudicationError("Test error")
        assert "Test error" in str(error)

    def test_error_with_findings(self):
        """Test error with findings."""
        finding = MockFinding()
        error = GlobalAdjudicationError("Test", findings=[finding])
        assert len(error.findings) == 1

    def test_exception_inheritance(self):
        """Test error inherits from Exception."""
        error = GlobalAdjudicationError("Test")
        assert isinstance(error, Exception)


class TestConflictInfo:
    """Test ConflictInfo dataclass."""

    def test_create_conflict_info(self):
        """Test creating conflict info."""
        info = ConflictInfo(
            conflict_type="TEST_CONFLICT",
            finding_ids=["f1", "f2"],
            details="Test details",
        )
        assert info.conflict_type == "TEST_CONFLICT"
        assert len(info.finding_ids) == 2

    def test_to_dict(self):
        """Test converting to dictionary."""
        info = ConflictInfo(
            conflict_type="TEST",
            finding_ids=["f1"],
            details="Test",
        )
        d = info.to_dict()
        assert d["conflict_type"] == "TEST"
        assert d["finding_ids"] == ["f1"]


class TestConsistencyCheckResult:
    """Test ConsistencyCheckResult dataclass."""

    def test_passed_result(self):
        """Test passed result."""
        result = ConsistencyCheckResult(passed=True, findings_checked=10)
        assert result.passed is True
        assert result.findings_checked == 10
        assert len(result.conflicts) == 0

    def test_failed_result(self):
        """Test failed result."""
        conflict = ConflictInfo("TEST", [], "Test")
        result = ConsistencyCheckResult(
            passed=False,
            findings_checked=5,
            conflicts=[conflict],
        )
        assert result.passed is False
        assert len(result.conflicts) == 1

    def test_to_dict(self):
        """Test converting to dictionary."""
        result = ConsistencyCheckResult(passed=True, findings_checked=10)
        d = result.to_dict()
        assert d["checked"] is True
        assert d["passed"] is True
        assert d["findings_checked"] == 10
        assert d["violations"] == 0
        assert d["warnings"] == 0
        assert d["fixed"] == 0

    def test_to_dict_with_warnings(self):
        """Test converting to dictionary with warnings."""
        result = ConsistencyCheckResult(
            passed=True,
            findings_checked=10,
            warnings=["warning1", "warning2"],
            fixed_count=3,
        )
        d = result.to_dict()
        assert d["warnings"] == 2
        assert d["fixed"] == 3


class TestGenerateLogicalVulnId:
    """Test generate_logical_vuln_id function."""

    def test_generate_basic(self):
        """Test basic ID generation."""
        finding = MockFinding(rule_id="rule-001")
        vuln_id = generate_logical_vuln_id(finding)
        assert vuln_id.startswith("vuln_")
        assert len(vuln_id) == 21  # "vuln_" + 16 hex chars

    def test_same_rule_same_file_same_id(self):
        """Test same rule + file produces same ID."""
        finding1 = MockFinding(rule_id="rule-001")
        finding2 = MockFinding(rule_id="rule-001")
        id1 = generate_logical_vuln_id(finding1)
        id2 = generate_logical_vuln_id(finding2)
        assert id1 == id2

    def test_different_rule_different_id(self):
        """Test different rule produces different ID."""
        finding1 = MockFinding(rule_id="rule-001")
        finding2 = MockFinding(rule_id="rule-002")
        id1 = generate_logical_vuln_id(finding1)
        id2 = generate_logical_vuln_id(finding2)
        assert id1 != id2

    def test_different_file_different_id(self):
        """Test different file produces different ID."""
        finding1 = MockFinding(rule_id="rule-001", location=MockLocation(file="a.py"))
        finding2 = MockFinding(rule_id="rule-001", location=MockLocation(file="b.py"))
        id1 = generate_logical_vuln_id(finding1)
        id2 = generate_logical_vuln_id(finding2)
        assert id1 != id2


class TestAdjudicationConsistencyChecker:
    """Test AdjudicationConsistencyChecker class."""

    def test_empty_findings_pass(self):
        """Test empty findings pass."""
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([])
        assert result.passed is True

    def test_single_valid_finding_passes(self):
        """Test single valid finding passes."""
        finding = MockFinding(
            finding_id="f1",
            exploitability="exploitable",
            final_status="exploitable",
        )
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([finding])
        assert result.passed is True

    def test_consistent_findings_pass(self):
        """Test multiple consistent findings pass."""
        findings = [
            MockFinding(
                finding_id="f1",
                rule_id="r1",
                exploitability="exploitable",
                final_status="exploitable",
            ),
            MockFinding(
                finding_id="f2",
                rule_id="r2",
                exploitability="conditional",
                final_status="conditional",
            ),
        ]
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings(findings)
        assert result.passed is True


class TestRule1ExploitabilityStatusMismatch:
    """Test Rule 1: Exploitability must match final_status."""

    def test_exploitable_status_mismatch(self):
        """Test EXPLOITABLE with NOT_EXPLOITABLE status fails."""
        finding = MockFinding(
            finding_id="f1",
            exploitability="exploitable",
            final_status="not_exploitable",
        )
        checker = AdjudicationConsistencyChecker(strict=False)
        result = checker.validate_findings([finding])
        assert result.passed is False
        assert any(c.conflict_type == "RULE_1_EXPLOITABILITY_STATUS_MISMATCH"
                   for c in result.conflicts)

    def test_not_exploitable_status_mismatch(self):
        """Test NOT_EXPLOITABLE with EXPLOITABLE status fails."""
        finding = MockFinding(
            finding_id="f1",
            exploitability="not_exploitable",
            final_status="exploitable",
        )
        checker = AdjudicationConsistencyChecker(strict=False)
        result = checker.validate_findings([finding])
        assert result.passed is False

    def test_exploitable_match_passes(self):
        """Test EXPLOITABLE with EXPLOITABLE status passes."""
        finding = MockFinding(
            finding_id="f1",
            exploitability="exploitable",
            final_status="exploitable",
        )
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([finding])
        assert result.passed is True

    def test_not_exploitable_match_passes(self):
        """Test NOT_EXPLOITABLE with NOT_EXPLOITABLE status passes."""
        finding = MockFinding(
            finding_id="f1",
            exploitability="not_exploitable",
            final_status="not_exploitable",
        )
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([finding])
        assert result.passed is True


class TestRule2StatusConflict:
    """Test Rule 2: Same ID cannot have EXPLOITABLE + NOT_EXPLOITABLE."""

    def test_same_id_conflict(self):
        """Test same logical_vuln_id with conflicting statuses fails."""
        findings = [
            MockFinding(
                finding_id="f1",
                rule_id="r1",
                source="semgrep",
                final_status="exploitable",
                logical_vuln_id="vuln_abc123",
            ),
            MockFinding(
                finding_id="f2",
                rule_id="r1",
                source="codeql",
                final_status="not_exploitable",
                logical_vuln_id="vuln_abc123",
            ),
        ]
        checker = AdjudicationConsistencyChecker(strict=False)
        result = checker.validate_findings(findings)
        assert result.passed is False
        assert any(c.conflict_type == "RULE_2_STATUS_CONFLICT"
                   for c in result.conflicts)

    def test_same_id_same_status_passes(self):
        """Test same logical_vuln_id with same status passes."""
        findings = [
            MockFinding(
                finding_id="f1",
                rule_id="r1",
                final_status="exploitable",
                logical_vuln_id="vuln_abc123",
            ),
            MockFinding(
                finding_id="f2",
                rule_id="r1",
                final_status="exploitable",
                logical_vuln_id="vuln_abc123",
            ),
        ]
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings(findings)
        assert result.passed is True

    def test_different_ids_no_conflict(self):
        """Test different logical_vuln_id no conflict."""
        findings = [
            MockFinding(
                finding_id="f1",
                rule_id="r1",
                final_status="exploitable",
                logical_vuln_id="vuln_abc123",
            ),
            MockFinding(
                finding_id="f2",
                rule_id="r2",
                final_status="not_exploitable",
                logical_vuln_id="vuln_xyz789",
            ),
        ]
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings(findings)
        assert result.passed is True


class TestRule3CrossEngineConflict:
    """Test Rule 3: No cross-engine status conflicts."""

    def test_cross_engine_conflict(self):
        """Test different engines with conflicting statuses fails."""
        findings = [
            MockFinding(
                finding_id="f1",
                rule_id="r1",
                source="semgrep",
                final_status="exploitable",
                logical_vuln_id="vuln_abc123",
            ),
            MockFinding(
                finding_id="f2",
                rule_id="r1",
                source="agent",
                final_status="not_exploitable",
                logical_vuln_id="vuln_abc123",
            ),
        ]
        checker = AdjudicationConsistencyChecker(strict=False)
        result = checker.validate_findings(findings)
        assert result.passed is False
        assert any(c.conflict_type == "RULE_3_CROSS_ENGINE_CONFLICT"
                   for c in result.conflicts)

    def test_cross_engine_same_status_passes(self):
        """Test different engines with same status passes."""
        findings = [
            MockFinding(
                finding_id="f1",
                rule_id="r1",
                source="semgrep",
                final_status="conditional",
                logical_vuln_id="vuln_abc123",
            ),
            MockFinding(
                finding_id="f2",
                rule_id="r1",
                source="codeql",
                final_status="conditional",
                logical_vuln_id="vuln_abc123",
            ),
        ]
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings(findings)
        assert result.passed is True


class TestRule4StatusRegression:
    """Test Rule 4: No status regression."""

    def test_status_regression(self):
        """Test status regression fails."""
        findings = [
            MockFinding(
                finding_id="f1",
                rule_id="r1",
                final_status="exploitable",
                logical_vuln_id="vuln_abc123",
            ),
            MockFinding(
                finding_id="f2",
                rule_id="r1",
                final_status="informational",
                logical_vuln_id="vuln_abc123",
            ),
        ]
        checker = AdjudicationConsistencyChecker(strict=False)
        result = checker.validate_findings(findings)
        assert result.passed is False
        assert any(c.conflict_type == "RULE_4_STATUS_REGRESSION"
                   for c in result.conflicts)

    def test_adjacent_levels_no_regression(self):
        """Test adjacent status levels don't trigger regression."""
        findings = [
            MockFinding(
                finding_id="f1",
                rule_id="r1",
                final_status="conditional",
                logical_vuln_id="vuln_abc123",
            ),
            MockFinding(
                finding_id="f2",
                rule_id="r1",
                final_status="exploitable",
                logical_vuln_id="vuln_abc123",
            ),
        ]
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings(findings)
        # Adjacent levels (2 and 3) should not trigger regression
        assert result.passed is True


class TestRule5MissingFinalStatus:
    """Test Rule 5: final_status cannot be None."""

    def test_missing_final_status(self):
        """Test missing final_status fails."""
        finding = MockFinding(
            finding_id="f1",
            final_status=None,
        )
        checker = AdjudicationConsistencyChecker(strict=False)
        result = checker.validate_findings([finding])
        assert result.passed is False
        assert any(c.conflict_type == "RULE_5_MISSING_FINAL_STATUS"
                   for c in result.conflicts)

    def test_present_final_status_passes(self):
        """Test present final_status passes."""
        finding = MockFinding(
            finding_id="f1",
            final_status="conditional",
        )
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([finding])
        assert result.passed is True


class TestStrictMode:
    """Test strict mode behavior."""

    def test_strict_mode_raises(self):
        """Test strict mode raises exception."""
        finding = MockFinding(
            finding_id="f1",
            exploitability="exploitable",
            final_status="not_exploitable",
        )
        checker = AdjudicationConsistencyChecker(strict=True)
        with pytest.raises(GlobalAdjudicationError):
            checker.validate_findings([finding])

    def test_non_strict_mode_returns(self):
        """Test non-strict mode returns result."""
        finding = MockFinding(
            finding_id="f1",
            exploitability="exploitable",
            final_status="not_exploitable",
        )
        checker = AdjudicationConsistencyChecker(strict=False)
        result = checker.validate_findings([finding])
        assert isinstance(result, ConsistencyCheckResult)
        assert result.passed is False


class TestValidateConsistencyFunction:
    """Test validate_consistency convenience function."""

    def test_function_basic(self):
        """Test basic function call."""
        findings = [
            MockFinding(
                finding_id="f1",
                final_status="conditional",
            )
        ]
        result = validate_consistency(findings, strict=False)
        assert result.passed is True

    def test_function_with_conflict(self):
        """Test function with conflict."""
        findings = [
            MockFinding(
                finding_id="f1",
                exploitability="not_exploitable",
                final_status="exploitable",
            )
        ]
        result = validate_consistency(findings, strict=False)
        assert result.passed is False


class TestEdgeCases:
    """Test edge cases."""

    def test_no_exploitability_field(self):
        """Test finding without exploitability field."""
        finding = MockFinding(
            finding_id="f1",
            final_status="conditional",
        )
        finding.exploitability = None
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([finding])
        assert result.passed is True

    def test_case_insensitive_status(self):
        """Test case-insensitive status matching."""
        finding = MockFinding(
            finding_id="f1",
            exploitability="EXPLOITABLE",
            final_status="exploitable",
        )
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([finding])
        assert result.passed is True

    def test_whitespace_in_status(self):
        """Test whitespace handling in status."""
        finding = MockFinding(
            finding_id="f1",
            exploitability="  exploitable  ",
            final_status="exploitable",
        )
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([finding])
        assert result.passed is True

    def test_multiple_conflicts(self):
        """Test multiple conflicts detected."""
        findings = [
            MockFinding(
                finding_id="f1",
                exploitability="exploitable",
                final_status="not_exploitable",
            ),
            MockFinding(
                finding_id="f2",
                final_status=None,
            ),
        ]
        checker = AdjudicationConsistencyChecker(strict=False)
        result = checker.validate_findings(findings)
        assert result.passed is False
        assert len(result.conflicts) >= 2

    def test_large_batch(self):
        """Test large batch of findings."""
        findings = [
            MockFinding(
                finding_id=f"f{i}",
                rule_id=f"r{i % 10}",
                final_status="conditional",
            )
            for i in range(100)
        ]
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings(findings)
        assert result.passed is True
        assert result.findings_checked == 100


class TestMetadataIntegration:
    """Test metadata integration."""

    def test_result_to_dict_metadata(self):
        """Test result to_dict for metadata storage."""
        result = ConsistencyCheckResult(
            passed=True,
            findings_checked=50,
        )
        d = result.to_dict()
        assert "checked" in d
        assert "passed" in d
        assert "findings_checked" in d
        assert "violations" in d
        assert "error" in d

    def test_conflict_to_dict_metadata(self):
        """Test conflict to_dict for metadata storage."""
        conflict = ConflictInfo(
            conflict_type="TEST_CONFLICT",
            finding_ids=["f1", "f2"],
            details="Test conflict details",
        )
        d = conflict.to_dict()
        assert "conflict_type" in d
        assert "finding_ids" in d
        assert "details" in d


class TestStatusAliases:
    """Test status alias handling."""

    def test_safe_alias(self):
        """Test 'safe' as alias for 'not_exploitable'."""
        finding = MockFinding(
            finding_id="f1",
            exploitability="safe",
            final_status="not_exploitable",
        )
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([finding])
        assert result.passed is True

    def test_confirmed_alias(self):
        """Test 'confirmed' as alias for 'exploitable'."""
        finding = MockFinding(
            finding_id="f1",
            exploitability="confirmed",
            final_status="exploitable",
        )
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([finding])
        assert result.passed is True


class TestRule2SeverityTooLowForExploitable:
    """Test RULE_2: EXPLOITABLE finding must have severity >= MEDIUM."""

    def test_exploitable_with_low_severity_fails(self):
        """Test EXPLOITABLE with LOW severity fails."""
        finding = MockFinding(
            finding_id="f1",
            final_status="exploitable",
            severity="low",
        )
        checker = AdjudicationConsistencyChecker(strict=False)
        result = checker.validate_findings([finding])
        assert result.passed is False
        assert any(c.conflict_type == "RULE_2_SEVERITY_TOO_LOW_FOR_EXPLOITABLE"
                   for c in result.conflicts)

    def test_exploitable_with_info_severity_fails(self):
        """Test EXPLOITABLE with INFO severity fails."""
        finding = MockFinding(
            finding_id="f1",
            final_status="exploitable",
            severity="info",
        )
        checker = AdjudicationConsistencyChecker(strict=False)
        result = checker.validate_findings([finding])
        assert result.passed is False
        assert any(c.conflict_type == "RULE_2_SEVERITY_TOO_LOW_FOR_EXPLOITABLE"
                   for c in result.conflicts)

    def test_exploitable_with_medium_severity_passes(self):
        """Test EXPLOITABLE with MEDIUM severity passes."""
        finding = MockFinding(
            finding_id="f1",
            final_status="exploitable",
            severity="medium",
        )
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([finding])
        assert result.passed is True

    def test_exploitable_with_high_severity_passes(self):
        """Test EXPLOITABLE with HIGH severity passes."""
        finding = MockFinding(
            finding_id="f1",
            final_status="exploitable",
            severity="high",
        )
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([finding])
        assert result.passed is True

    def test_exploitable_with_critical_severity_passes(self):
        """Test EXPLOITABLE with CRITICAL severity passes."""
        finding = MockFinding(
            finding_id="f1",
            final_status="exploitable",
            severity="critical",
        )
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([finding])
        assert result.passed is True

    def test_exploitable_with_no_severity_passes(self):
        """Test EXPLOITABLE without severity passes (no check)."""
        finding = MockFinding(
            finding_id="f1",
            final_status="exploitable",
            severity=None,
        )
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([finding])
        assert result.passed is True

    def test_strict_mode_raises_on_low_severity(self):
        """Test strict mode raises exception on LOW severity."""
        finding = MockFinding(
            finding_id="f1",
            final_status="exploitable",
            severity="low",
        )
        checker = AdjudicationConsistencyChecker(strict=True)
        with pytest.raises(GlobalAdjudicationError):
            checker.validate_findings([finding])


class TestRule5SeverityStatusWarning:
    """Test RULE_5: HIGH/CRITICAL severity with INFORMATIONAL status generates warning."""

    def test_high_severity_informational_status_warning(self):
        """Test HIGH severity with INFORMATIONAL status generates warning."""
        finding = MockFinding(
            finding_id="f1",
            rule_id="rule-001",
            final_status="informational",
            severity="high",
        )
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([finding])
        assert result.passed is True  # Warning doesn't fail
        assert len(result.warnings) == 1
        assert "RULE_5_SEVERITY_STATUS_INCONSISTENCY" in result.warnings[0]

    def test_critical_severity_informational_status_warning(self):
        """Test CRITICAL severity with INFORMATIONAL status generates warning."""
        finding = MockFinding(
            finding_id="f1",
            rule_id="rule-001",
            final_status="informational",
            severity="critical",
        )
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([finding])
        assert result.passed is True
        assert len(result.warnings) == 1
        assert "RULE_5_SEVERITY_STATUS_INCONSISTENCY" in result.warnings[0]

    def test_medium_severity_informational_status_no_warning(self):
        """Test MEDIUM severity with INFORMATIONAL status no warning."""
        finding = MockFinding(
            finding_id="f1",
            final_status="informational",
            severity="medium",
        )
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([finding])
        assert result.passed is True
        assert len(result.warnings) == 0

    def test_low_severity_informational_status_no_warning(self):
        """Test LOW severity with INFORMATIONAL status no warning."""
        finding = MockFinding(
            finding_id="f1",
            final_status="informational",
            severity="low",
        )
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([finding])
        assert result.passed is True
        assert len(result.warnings) == 0

    def test_high_severity_exploitable_status_no_warning(self):
        """Test HIGH severity with EXPLOITABLE status no warning."""
        finding = MockFinding(
            finding_id="f1",
            final_status="exploitable",
            severity="high",
        )
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([finding])
        assert result.passed is True
        assert len(result.warnings) == 0

    def test_multiple_warnings_collected(self):
        """Test multiple warnings are collected."""
        findings = [
            MockFinding(
                finding_id="f1",
                rule_id="rule-001",
                final_status="informational",
                severity="high",
            ),
            MockFinding(
                finding_id="f2",
                rule_id="rule-002",
                final_status="informational",
                severity="critical",
            ),
        ]
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings(findings)
        assert result.passed is True
        assert len(result.warnings) == 2

    def test_warning_includes_finding_id_and_rule_id(self):
        """Test warning message includes finding_id and rule_id."""
        finding = MockFinding(
            finding_id="f1",
            rule_id="rule-001",
            final_status="informational",
            severity="high",
        )
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings([finding])
        assert "f1" in result.warnings[0]
        assert "rule-001" in result.warnings[0]


class TestConsistencyCheckResultWarnings:
    """Test ConsistencyCheckResult warnings field."""

    def test_warnings_default_empty(self):
        """Test warnings default to empty list."""
        result = ConsistencyCheckResult(passed=True)
        assert result.warnings == []

    def test_fixed_count_default_zero(self):
        """Test fixed_count defaults to 0."""
        result = ConsistencyCheckResult(passed=True)
        assert result.fixed_count == 0

    def test_warnings_can_be_set(self):
        """Test warnings can be set."""
        result = ConsistencyCheckResult(
            passed=True,
            warnings=["warning1", "warning2"],
        )
        assert len(result.warnings) == 2

    def test_fixed_count_can_be_set(self):
        """Test fixed_count can be set."""
        result = ConsistencyCheckResult(
            passed=True,
            fixed_count=5,
        )
        assert result.fixed_count == 5


class TestCombinedRules:
    """Test combined rule scenarios."""

    def test_exploitable_low_severity_and_high_info_warning(self):
        """Test both RULE_2 violation and RULE_5 warning in same batch."""
        findings = [
            MockFinding(
                finding_id="f1",
                rule_id="r1",
                final_status="exploitable",
                severity="low",  # RULE_2 violation
            ),
            MockFinding(
                finding_id="f2",
                rule_id="r2",
                final_status="informational",
                severity="high",  # RULE_5 warning
            ),
        ]
        checker = AdjudicationConsistencyChecker(strict=False)
        result = checker.validate_findings(findings)
        assert result.passed is False  # RULE_2 violation fails
        assert len(result.conflicts) >= 1
        assert len(result.warnings) >= 1

    def test_all_rules_pass_with_warnings(self):
        """Test all rules pass but warnings generated."""
        findings = [
            MockFinding(
                finding_id="f1",
                rule_id="r1",
                exploitability="exploitable",
                final_status="exploitable",
                severity="high",
            ),
            MockFinding(
                finding_id="f2",
                rule_id="r2",
                exploitability="conditional",
                final_status="conditional",
                severity="medium",
            ),
            MockFinding(
                finding_id="f3",
                rule_id="r3",
                final_status="informational",
                severity="critical",  # RULE_5 warning
            ),
        ]
        checker = AdjudicationConsistencyChecker()
        result = checker.validate_findings(findings)
        assert result.passed is True
        assert len(result.warnings) == 1
        assert result.findings_checked == 3
