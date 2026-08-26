"""
Unit tests for VerificationGatekeeper - P8-08f component.

Tests cover:
1. Clear false positive detection
2. Strong evidence detection
3. Low confidence + low severity handling
4. Auto-decision logic
5. Batch processing
"""

import pytest

from src.layers.l3_analysis.models import (
    CodeLocation,
    Finding,
    FindingType,
    SeverityLevel,
)
from src.layers.l3_analysis.verification.verification_gatekeeper import (
    VerificationGatekeeper,
    BatchGatekeeper,
    AutoDecision,
    should_verify_finding,
)


class TestVerificationGatekeeper:
    """Test suite for VerificationGatekeeper class."""

    def test_init(self):
        """Test initialization."""
        gatekeeper = VerificationGatekeeper()
        assert gatekeeper.verification_threshold == 0.5

    def test_custom_threshold(self):
        """Test custom verification threshold."""
        gatekeeper = VerificationGatekeeper(verification_threshold=0.7)
        assert gatekeeper.verification_threshold == 0.7


class TestFalsePositiveDetection:
    """Test false positive detection."""

    def make_finding(self, snippet: str, confidence: float = 0.8) -> Finding:
        """Helper to create a test finding."""
        return Finding(
            id="test-001",
            rule_id="test_rule",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.MEDIUM,
            confidence=confidence,
            title="Test Finding",
            description="Test description",
            fix_suggestion="Fix it",
            location=CodeLocation(
                file="test.py",
                line=10,
                end_line=10,
                snippet=snippet,
            ),
            source="agent",
        )

    def test_return_only_string_rejected(self):
        """Test finding with only return statement is rejected."""
        gatekeeper = VerificationGatekeeper()

        finding = self.make_finding('return "File: " + filename')

        result = gatekeeper.should_verify(finding)

        assert result.decision == AutoDecision.FALSE_POSITIVE
        assert result.should_verify is False

    def test_only_assignment_rejected(self):
        """Test finding with only variable assignment is rejected."""
        gatekeeper = VerificationGatekeeper()

        finding = self.make_finding('message = "User: " + input')

        result = gatekeeper.should_verify(finding)

        assert result.decision == AutoDecision.FALSE_POSITIVE
        assert result.should_verify is False

    def test_no_execution_description_rejected(self):
        """Test finding with "no actual" in description is rejected."""
        gatekeeper = VerificationGatekeeper()

        finding = Finding(
            id="test-001",
            rule_id="path_traversal",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.7,
            title="Path Traversal",
            description="Possible path traversal but no actual file operation",
            fix_suggestion="Fix it",
            location=CodeLocation(
                file="test.py",
                line=10,
                end_line=10,
                snippet='path = user_input',
            ),
            source="agent",
        )

        result = gatekeeper.should_verify(finding)

        assert result.decision == AutoDecision.FALSE_POSITIVE
        assert result.should_verify is False


class TestStrongEvidenceDetection:
    """Test strong evidence detection."""

    def test_poc_in_metadata_confirmed(self):
        """Test finding with PoC in metadata is confirmed."""
        gatekeeper = VerificationGatekeeper()

        finding = Finding(
            id="test-001",
            rule_id="cmd_injection",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.CRITICAL,
            confidence=0.95,
            title="Command Injection",
            description="Confirmed command injection",
            fix_suggestion="Use safe alternatives",
            location=CodeLocation(
                file="test.py",
                line=10,
                end_line=10,
                snippet='os.system(user_input)',
            ),
            source="agent",
            metadata={"poc": {"url": "http://target/cmd", "command": "whoami"}},
        )

        result = gatekeeper.should_verify(finding)

        assert result.decision == AutoDecision.CONFIRMED
        assert result.should_verify is False

    def test_poc_in_description_confirmed(self):
        """Test finding with PoC mention in description is confirmed."""
        gatekeeper = VerificationGatekeeper()

        finding = Finding(
            id="test-002",
            rule_id="sqli",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.92,
            title="SQL Injection",
            description="Working PoC: OR 1=1 returns all rows",
            fix_suggestion="Use parameterized queries",
            location=CodeLocation(
                file="test.py",
                line=20,
                end_line=20,
                snippet='execute(f"SELECT * FROM users WHERE id = {user_id}")',
            ),
            source="agent",
            # Structured PoC record (dict) counts as strong evidence; the
            # free-text "Working PoC" in description alone is NOT trusted.
            metadata={"poc": {"payload": "OR 1=1", "result": "all rows"}},
        )

        result = gatekeeper.should_verify(finding)

        assert result.decision == AutoDecision.CONFIRMED
        assert result.should_verify is False

    def test_high_confidence_without_poc_needs_verification(self):
        """Test high confidence without PoC needs verification."""
        gatekeeper = VerificationGatekeeper()

        finding = Finding(
            id="test-003",
            rule_id="xss",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            title="XSS",
            description="Possible XSS via innerHTML",
            fix_suggestion="Use textContent",
            location=CodeLocation(
                file="test.js",
                line=15,
                end_line=15,
                snippet='el.innerHTML = userInput',
            ),
            source="agent",
        )

        result = gatekeeper.should_verify(finding)

        # High confidence but no strong evidence → needs verification
        assert result.decision == AutoDecision.REQUIRES_VERIFICATION
        assert result.should_verify is True


class TestLowSeverityHandling:
    """Test low confidence + low severity handling."""

    def test_low_confidence_low_severity_skipped(self):
        """Test low confidence + low severity is skipped."""
        gatekeeper = VerificationGatekeeper(verification_threshold=0.5)

        finding = Finding(
            id="test-001",
            rule_id="info_leak",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.INFO,
            confidence=0.3,
            title="Information Disclosure",
            description="Possible information leak",
            fix_suggestion="Remove debug output",
            location=CodeLocation(
                file="test.py",
                line=1,
                end_line=1,
                snippet='print(debug_info)',
            ),
            source="agent",
        )

        result = gatekeeper.should_verify(finding)

        assert result.decision == AutoDecision.NEEDS_REVIEW
        assert result.should_verify is False

    def test_low_confidence_high_severity_needs_verification(self):
        """Test low confidence + high severity needs verification."""
        gatekeeper = VerificationGatekeeper()

        finding = Finding(
            id="test-001",
            rule_id="rce",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.CRITICAL,
            confidence=0.4,
            title="RCE",
            description="Possible remote code execution",
            fix_suggestion="Avoid eval",
            location=CodeLocation(
                file="test.py",
                line=10,
                end_line=10,
                snippet='eval(user_input)',
            ),
            source="agent",
        )

        result = gatekeeper.should_verify(finding)

        # High severity needs verification even with low confidence
        assert result.decision == AutoDecision.REQUIRES_VERIFICATION
        assert result.should_verify is True


class TestConfirmedExploitability:
    """Test confirmed exploitability auto-confirm."""

    def test_confirmed_exploitability_auto_confirms(self):
        """Test finding with confirmed exploitability is auto-confirmed."""
        gatekeeper = VerificationGatekeeper()

        finding = Finding(
            id="test-001",
            rule_id="sql_injection",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            exploitability="confirmed",
            title="SQL Injection",
            description="Confirmed SQL injection",
            fix_suggestion="Use parameterized queries",
            location=CodeLocation(
                file="test.py",
                line=10,
                end_line=10,
                snippet='execute(f"SELECT * FROM users WHERE id = {user_id}")',
            ),
            source="agent",
            # Phase 18/P6: the "confirmed" label is trusted only when backed
            # by a real source->sink dataflow (set by the evidence gate).
            metadata={"dataflow_backed": True},
        )

        result = gatekeeper.should_verify(finding)

        assert result.decision == AutoDecision.CONFIRMED
        assert result.should_verify is False

    def test_exploitable_auto_confirms(self):
        """Test finding with exploitable status is auto-confirmed."""
        gatekeeper = VerificationGatekeeper()

        finding = Finding(
            id="test-001",
            rule_id="cmd_injection",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.CRITICAL,
            confidence=0.85,
            exploitability="exploitable",
            title="Command Injection",
            description="Exploitable command injection",
            fix_suggestion="Use subprocess",
            location=CodeLocation(
                file="test.py",
                line=10,
                end_line=10,
                snippet='os.system(cmd)',
            ),
            source="agent",
            # Phase 18/P6: dataflow-backed EXPLOITABLE auto-confirms.
            metadata={"dataflow_backed": True},
        )

        result = gatekeeper.should_verify(finding)

        assert result.decision == AutoDecision.CONFIRMED
        assert result.should_verify is False

    def test_exploitable_without_dataflow_backing_requires_verification(self):
        """Phase 18/P6: an EXPLOITABLE label without dataflow backing (e.g. a
        LLM-only override) must still require verification — never auto-confirm
        a label that no real source->sink dataflow supports.
        """
        gatekeeper = VerificationGatekeeper()

        finding = Finding(
            id="test-llm-override",
            rule_id="cmd_injection",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.85,
            exploitability="exploitable",
            title="Command Injection",
            description="Possibly exploitable",
            fix_suggestion="Use subprocess",
            location=CodeLocation(
                file="test.py",
                line=10,
                end_line=10,
                snippet='os.system(cmd)',
            ),
            source="agent",
        )

        result = gatekeeper.should_verify(finding)

        assert result.should_verify is True


class TestAutoDecision:
    """Test auto-decision logic."""

    def test_auto_decide_confirmed(self):
        """Test auto-decide returns 'confirmed' for strong evidence."""
        gatekeeper = VerificationGatekeeper()

        reason = "Strong evidence (PoC) with high confidence - auto-confirm"
        decision = gatekeeper.auto_decide(None, reason)

        assert decision == "confirmed"

    def test_auto_decide_false_positive(self):
        """Test auto-decide returns 'false_positive' for FP patterns."""
        gatekeeper = VerificationGatekeeper()

        reason = "Clear false positive pattern detected"
        decision = gatekeeper.auto_decide(None, reason)

        assert decision == "false_positive"

    def test_auto_decide_needs_review(self):
        """Test auto-decide returns 'needs_review' for low priority."""
        gatekeeper = VerificationGatekeeper()

        reason = "Low confidence (0.30) + low severity - needs review only"
        decision = gatekeeper.auto_decide(None, reason)

        assert decision == "needs_review"


class TestBatchGatekeeper:
    """Test batch gatekeeper functionality."""

    def make_finding(self, id: str, severity: SeverityLevel, confidence: float) -> Finding:
        """Helper to create a test finding."""
        return Finding(
            id=id,
            rule_id="test_rule",
            type=FindingType.VULNERABILITY,
            severity=severity,
            confidence=confidence,
            title=f"Finding {id}",
            description="Test description",
            fix_suggestion="Fix it",
            location=CodeLocation(
                file="test.py",
                line=1,
                end_line=1,
                snippet="code",
            ),
            source="agent",
        )

    def test_categorize_findings(self):
        """Test findings are categorized correctly."""
        gatekeeper = BatchGatekeeper()

        findings = [
            # Low priority - should be needs_review
            self.make_finding("f1", SeverityLevel.INFO, 0.3),
            # High priority - needs verification
            self.make_finding("f2", SeverityLevel.HIGH, 0.7),
        ]

        categories = gatekeeper.categorize_findings(findings)

        assert "needs_review" in categories
        assert "requires_verification" in categories
        assert len(categories["needs_review"]) >= 1
        assert len(categories["requires_verification"]) >= 1

    def test_get_stats(self):
        """Test statistics calculation."""
        gatekeeper = BatchGatekeeper()

        findings = [
            self.make_finding(f"f{i}", SeverityLevel.MEDIUM, 0.5)
            for i in range(10)
        ]

        categories = gatekeeper.categorize_findings(findings)
        stats = gatekeeper.get_stats(categories)

        assert stats["confirmed"] + stats["false_positive"] + stats["needs_review"] + stats["requires_verification"] == 10


class TestConvenienceFunction:
    """Test the convenience function."""

    def test_returns_tuple(self):
        """Test function returns (bool, str) tuple."""
        finding = Finding(
            id="test",
            rule_id="test",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.MEDIUM,
            confidence=0.5,
            title="Test",
            description="Test",
            fix_suggestion=None,
            location=CodeLocation(
                file="test.py",
                line=1,
                end_line=1,
                snippet="code",
            ),
            source="agent",
        )

        should_verify, reason = should_verify_finding(finding)

        assert isinstance(should_verify, bool)
        assert isinstance(reason, str)


class TestIntegrationScenarios:
    """Integration tests for real-world scenarios."""

    def test_clear_fp_skipped(self):
        """Test clear false positive is skipped."""
        gatekeeper = VerificationGatekeeper()

        finding = Finding(
            id="fp-001",
            rule_id="path_traversal",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.7,
            title="Path Traversal?",
            description="Returns only file name string",
            fix_suggestion=None,
            location=CodeLocation(
                file="handler.py",
                line=10,
                end_line=10,
                snippet='return "File: " + filename',
            ),
            source="agent",
        )

        result = gatekeeper.should_verify(finding)

        assert result.should_verify is False
        assert result.decision == AutoDecision.FALSE_POSITIVE

    def test_poc_confirmed_skipped(self):
        """Test finding with PoC is confirmed (no verification)."""
        gatekeeper = VerificationGatekeeper()

        finding = Finding(
            id="poc-001",
            rule_id="rce",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.CRITICAL,
            confidence=0.95,
            title="RCE with PoC",
            description="Remote code execution confirmed with working PoC",
            fix_suggestion="Remove eval",
            location=CodeLocation(
                file="route.py",
                line=20,
                end_line=20,
                snippet='eval(request.data["cmd"])',
            ),
            source="agent",
            metadata={"poc": {"command": "python -c 'import socket; ...'"}},
        )

        result = gatekeeper.should_verify(finding)

        assert result.should_verify is False
        assert result.decision == AutoDecision.CONFIRMED

    def test_uncertain_needs_verification(self):
        """Test uncertain finding needs verification."""
        gatekeeper = VerificationGatekeeper()

        finding = Finding(
            id="uncertain-001",
            rule_id="xss",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.7,
            title="Possible XSS",
            description="Possible XSS via template rendering",
            fix_suggestion="Escape output",
            location=CodeLocation(
                file="view.py",
                line=15,
                end_line=15,
                snippet='render_template(user_input)',
            ),
            source="agent",
        )

        result = gatekeeper.should_verify(finding)

        assert result.should_verify is True
        assert result.decision == AutoDecision.REQUIRES_VERIFICATION
