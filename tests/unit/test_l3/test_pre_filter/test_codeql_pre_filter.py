"""
Unit tests for CodeQLPreFilter - P8-08d component.

Tests cover:
1. Rule matching with wildcards
2. Confidence adjustment
3. XSS response type detection
4. Finding acceptance logic
"""

import pytest

from src.layers.l3_analysis.models import (
    CodeLocation,
    Finding,
    FindingType,
    SeverityLevel,
)
from src.layers.l3_analysis.pre_filter.codeql_pre_filter import (
    CodeQLPreFilter,
    RuleAdjustment,
    should_accept_codeql_finding,
)


class TestCodeQLPreFilter:
    """Test suite for CodeQLPreFilter class."""

    def test_init(self):
        """Test initialization."""
        pre_filter = CodeQLPreFilter()
        assert pre_filter is not None
        assert pre_filter.strict_mode is False


class TestRuleMatching:
    """Test rule ID pattern matching."""

    def test_exact_match(self):
        """Test exact rule ID match."""
        pre_filter = CodeQLPreFilter()

        assert pre_filter._rule_matches_pattern("javascript/xss", "javascript/xss")
        assert pre_filter._rule_matches_pattern("python/xss", "python/xss")

    def test_wildcard_match(self):
        """Test wildcard pattern matching."""
        pre_filter = CodeQLPreFilter()

        assert pre_filter._rule_matches_pattern("javascript/xss", "*/xss*")
        assert pre_filter._rule_matches_pattern("python/xss", "*/xss*")
        # Test wildcard at start
        assert pre_filter._rule_matches_pattern("custom/generic-rule", "*/generic*")
        # Test wildcard at end
        assert pre_filter._rule_matches_pattern("generic-rule/subtype", "generic-rule*")

    def test_no_match(self):
        """Test non-matching patterns."""
        pre_filter = CodeQLPreFilter()

        assert not pre_filter._rule_matches_pattern("sql/injection", "*/xss*")
        assert not pre_filter._rule_matches_pattern("javascript/xss", "python/*")


class TestRuleAdjustments:
    """Test rule adjustment retrieval."""

    def test_default_adjustments(self):
        """Test default rule adjustments are returned."""
        pre_filter = CodeQLPreFilter()

        adjustments = pre_filter.get_adjusted_rules()

        assert "javascript/xss" in adjustments
        assert "*/xss*" in adjustments

    def test_api_project_adjustments(self):
        """Test API project gets stricter XSS rules."""
        pre_filter = CodeQLPreFilter()

        adjustments = pre_filter.get_adjusted_rules(project_type="api")

        # API projects should have higher penalty for XSS
        xss_adj = adjustments.get("*/xss*")
        assert xss_adj is not None
        assert xss_adj.confidence_penalty >= 0.25

    def test_language_specific_adjustments(self):
        """Test language-specific adjustments."""
        pre_filter = CodeQLPreFilter()

        js_adjustments = pre_filter.get_adjusted_rules(language="javascript")
        python_adjustments = pre_filter.get_adjusted_rules(language="python")

        # JavaScript should have stricter XSS rules
        js_xss_adj = js_adjustments.get("javascript/xss")
        py_xss_adj = python_adjustments.get("javascript/xss")

        if js_xss_adj:
            assert js_xss_adj.confidence_penalty >= 0.2


class TestFindingAcceptance:
    """Test finding acceptance logic."""

    def make_finding(
        self,
        rule_id: str,
        confidence: float = 0.8,
        snippet: str = "code",
    ) -> Finding:
        """Helper to create a test finding."""
        return Finding(
            id="test-001",
            rule_id=rule_id,
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=confidence,
            title="Test Finding",
            description="Test description",
            fix_suggestion="Fix it",
            location=CodeLocation(
                file="test.js",
                line=10,
                end_line=10,
                snippet=snippet,
            ),
            source="codeql",
        )

    def test_low_confidence_xss_rejected(self):
        """Test low confidence XSS findings are rejected."""
        pre_filter = CodeQLPreFilter()

        finding = self.make_finding("javascript/xss", confidence=0.2)

        accept, reason = pre_filter.should_accept_finding(finding)

        # Should be rejected due to minimum confidence
        assert accept is False
        assert "minimum confidence" in reason.lower()

    def test_xss_with_json_rejected(self):
        """Test XSS with JSON response is rejected."""
        pre_filter = CodeQLPreFilter()

        finding = self.make_finding(
            "javascript/xss",
            confidence=0.8,
            snippet="res.json({ name: req.query.name })",
        )

        accept, reason = pre_filter.should_accept_finding(finding)

        assert accept is False
        assert "html response" in reason.lower() or "false positive" in reason.lower()

    def test_xss_with_html_accepted(self):
        """Test XSS with HTML rendering is accepted."""
        pre_filter = CodeQLPreFilter()

        finding = self.make_finding(
            "javascript/xss",
            confidence=0.8,
            snippet="document.getElementById('output').innerHTML = userInput",
        )

        accept, reason = pre_filter.should_accept_finding(finding)

        assert accept is True

    def test_non_xss_accepted(self):
        """Test non-XSS findings are accepted."""
        pre_filter = CodeQLPreFilter()

        finding = self.make_finding("sql/injection", confidence=0.7)

        accept, reason = pre_filter.should_accept_finding(finding)

        assert accept is True


class TestConfidenceAdjustment:
    """Test confidence adjustment."""

    def test_confidence_penalty_applied(self):
        """Test confidence penalty is applied."""
        pre_filter = CodeQLPreFilter()

        finding = Finding(
            id="test-001",
            rule_id="javascript/xss",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            title="XSS",
            description="XSS vulnerability",
            fix_suggestion="Escape output",
            location=CodeLocation(
                file="test.js",
                line=10,
                end_line=10,
                snippet="innerHTML = x",
            ),
            source="codeql",
        )

        adjusted = pre_filter.adjust_finding_confidence(finding)

        # Should have lower confidence
        assert adjusted.confidence < finding.confidence
        assert adjusted.metadata.get("codeql_adjusted") is True

    def test_non_adjusted_rule_unchanged(self):
        """Test rules without adjustments are unchanged."""
        pre_filter = CodeQLPreFilter()

        finding = Finding(
            id="test-001",
            rule_id="custom-rule",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.MEDIUM,
            confidence=0.7,
            title="Custom",
            description="Custom rule",
            fix_suggestion=None,
            location=CodeLocation(
                file="test.py",
                line=1,
                end_line=1,
                snippet="code",
            ),
            source="codeql",
        )

        adjusted = pre_filter.adjust_finding_confidence(finding)

        # Should be unchanged
        assert adjusted.confidence == finding.confidence


class TestHTMLResponseDetection:
    """Test HTML response detection."""

    def test_innerhtml_detected(self):
        """Test innerHTML pattern is detected."""
        pre_filter = CodeQLPreFilter()

        finding = Finding(
            id="test",
            rule_id="javascript/xss",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="XSS",
            description="XSS via innerHTML",
            fix_suggestion=None,
            location=CodeLocation(
                file="test.js",
                line=10,
                end_line=10,
                snippet="element.innerHTML = userInput",
            ),
            source="codeql",
        )

        assert pre_filter._confirms_html_response(finding) is True

    def test_document_write_detected(self):
        """Test document.write pattern is detected."""
        pre_filter = CodeQLPreFilter()

        finding = Finding(
            id="test",
            rule_id="javascript/xss",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="XSS",
            description="XSS via document.write",
            fix_suggestion=None,
            location=CodeLocation(
                file="test.js",
                line=10,
                end_line=10,
                snippet="document.write('<script>' + userInput + '</script>')",
            ),
            source="codeql",
        )

        assert pre_filter._confirms_html_response(finding) is True

    def test_json_response_not_html(self):
        """Test JSON response is not detected as HTML."""
        pre_filter = CodeQLPreFilter()

        finding = Finding(
            id="test",
            rule_id="javascript/xss",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="Not XSS",
            description="JSON response",
            fix_suggestion=None,
            location=CodeLocation(
                file="test.js",
                line=10,
                end_line=10,
                snippet="res.json({ data: userInput })",
            ),
            source="codeql",
        )

        assert pre_filter._confirms_html_response(finding) is False


class TestConvenienceFunction:
    """Test the convenience function."""

    def test_returns_tuple(self):
        """Test function returns (bool, str) tuple."""
        finding = Finding(
            id="test",
            rule_id="test",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.LOW,
            confidence=0.3,
            title="Test",
            description="Test",
            fix_suggestion=None,
            location=CodeLocation(
                file="test.js",
                line=1,
                end_line=1,
                snippet="code",
            ),
            source="codeql",
        )

        accept, reason = should_accept_codeql_finding(finding)

        assert isinstance(accept, bool)
        assert isinstance(reason, str)


class TestIntegrationScenarios:
    """Integration tests for real-world scenarios."""

    def test_api_xss_finding_rejected(self):
        """Test XSS finding in API project is rejected."""
        pre_filter = CodeQLPreFilter(strict_mode=True)

        adjustments = pre_filter.get_adjusted_rules(project_type="api")

        finding = Finding(
            id="xss-001",
            rule_id="javascript/xss",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.7,
            title="XSS in API",
            description="Possible XSS in API endpoint",
            fix_suggestion="Escape output",
            location=CodeLocation(
                file="api/users.js",
                line=20,
                end_line=20,
                snippet="res.json({ name: req.query.name })",
            ),
            source="codeql",
        )

        # Should be rejected: API + JSON response
        accept, reason = pre_filter.should_accept_finding(finding, adjustments)

        assert accept is False

    def test_web_xss_finding_accepted(self):
        """Test XSS finding in web app is accepted."""
        pre_filter = CodeQLPreFilter()

        finding = Finding(
            id="xss-002",
            rule_id="javascript/xss",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            title="XSS in web app",
            description="XSS via innerHTML",
            fix_suggestion="Use textContent",
            location=CodeLocation(
                file="web/views.js",
                line=15,
                end_line=15,
                snippet="document.getElementById('output').innerHTML = userInput",
            ),
            source="codeql",
        )

        accept, reason = pre_filter.should_accept_finding(finding)

        assert accept is True
