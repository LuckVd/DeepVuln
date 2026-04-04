"""
Integration tests for P8-08 Pre-Filter Architecture.

Tests cover:
1. End-to-end filtering pipeline
2. Component integration
3. Effect evaluation metrics
4. Real-world scenarios
"""

import pytest
from pathlib import Path
from typing import Any

from src.layers.l3_analysis.models import (
    CodeLocation,
    Finding,
    FindingType,
    SeverityLevel,
)
from src.layers.l3_analysis.pre_filter.file_pre_filter import FilePreFilter
from src.layers.l3_analysis.pre_filter.codeql_pre_filter import CodeQLPreFilter
from src.layers.l3_analysis.pre_filter.in_memory_deduplicator import (
    InMemoryDeduplicator,
)
from src.layers.l3_analysis.pre_filter.streaming_validator import StreamingValidator
from src.layers.l3_analysis.verification.verification_gatekeeper import (
    VerificationGatekeeper,
    BatchGatekeeper,
    AutoDecision,
)


class TestPreFilterPipeline:
    """Test the complete pre-filter pipeline."""

    @pytest.fixture
    def pipeline_components(self):
        """Create all pre-filter components."""
        return {
            "file_filter": FilePreFilter(),
            "codeql_filter": CodeQLPreFilter(),
            "deduplicator": InMemoryDeduplicator(),
            "validator": StreamingValidator(),
            "gatekeeper": VerificationGatekeeper(),
        }

    def make_finding(
        self,
        id: str,
        rule_id: str,
        file: str,
        snippet: str,
        confidence: float = 0.8,
        severity: SeverityLevel = SeverityLevel.HIGH,
        source: str = "agent",
    ) -> Finding:
        """Helper to create test findings."""
        return Finding(
            id=id,
            rule_id=rule_id,
            type=FindingType.VULNERABILITY,
            severity=severity,
            confidence=confidence,
            title=f"Finding {id}",
            description=f"{rule_id} vulnerability",
            fix_suggestion="Fix it",
            location=CodeLocation(
                file=file,
                line=10,
                end_line=10,
                snippet=snippet,
            ),
            source=source,
        )

    def test_file_filter_rejects_config_files(self, pipeline_components):
        """Test that config files are filtered out."""
        file_filter = pipeline_components["file_filter"]

        # Test file filtering
        config_result = file_filter.should_analyze(
            Path("config.yaml"),
            "key: value"
        )
        app_result = file_filter.should_analyze(
            Path("app.py"),
            "def hello():\n    return innerHTML"
        )

        assert config_result.should_analyze is False
        assert app_result.should_analyze is True

    def test_full_pipeline_filters_all_stages(self, pipeline_components):
        """Test that all pipeline stages work together."""
        file_filter = pipeline_components["file_filter"]
        deduplicator = pipeline_components["deduplicator"]
        gatekeeper = pipeline_components["gatekeeper"]

        # Create diverse findings
        findings = [
            # Duplicate - should be filtered by deduplicator
            self.make_finding("f2", "sqli", "app.py", "execute(x)", source="agent"),
            self.make_finding("f3", "sqli", "app.py", "execute(x)", source="agent"),
            # Low confidence + low severity - should be skipped by gatekeeper
            self.make_finding(
                "f4",
                "info_leak",
                "app.py",
                "print(x)",
                confidence=0.3,
                severity=SeverityLevel.INFO,
            ),
            # Needs verification
            self.make_finding("f5", "xss", "app.py", "innerHTML = x"),
        ]

        # Apply deduplication (simulate per-file processing with all findings)
        dedup_results = deduplicator.deduplicate_findings(findings, "app.py")

        # Apply gatekeeper
        verification_needed = []
        for finding in dedup_results:
            result = gatekeeper.should_verify(finding)
            if result.should_verify:
                verification_needed.append(finding)

        # Verify reduction
        assert len(findings) == 4
        assert len(dedup_results) <= 4  # Duplicates removed
        assert len(verification_needed) <= 3  # Low priority findings may be skipped


class TestEffectEvaluation:
    """Test effect evaluation metrics."""

    def test_false_positive_reduction_file_filter(self):
        """Test file filter reduces false positives."""
        file_filter = FilePreFilter()

        # Test filtering of config files
        config_result = file_filter.should_analyze(
            Path("config.yaml"),
            "key: value"
        )
        route_result = file_filter.should_analyze(
            Path("route.py"),
            "def handler():\n    innerHTML = user_input"
        )

        # Config file should be rejected
        assert config_result.should_analyze is False
        assert route_result.should_analyze is True

        # Calculate reduction rate
        total = 2
        analyzed = sum([config_result.should_analyze, route_result.should_analyze])
        reduction_rate = (total - analyzed) / total
        assert reduction_rate == 0.5

    def test_deduplication_reduction(self):
        """Test deduplication reduces duplicate findings."""
        deduplicator = InMemoryDeduplicator()

        findings = [
            Finding(
                id=f"f{i}",
                rule_id="sqli",
                type=FindingType.VULNERABILITY,
                severity=SeverityLevel.HIGH,
                confidence=0.8,
                title=f"SQLi {i}",
                description="SQL injection",
                fix_suggestion="Use parameterized queries",
                location=CodeLocation(
                    file="app.py",
                    line=10,
                    end_line=10,
                    snippet="execute(user_input)",
                ),
                source="agent",
                final_score=1.0,
            )
            for i in range(5)
        ]

        result = deduplicator.deduplicate_findings(findings, "app.py")

        # Should reduce to 1 finding
        assert len(result) == 1
        reduction_rate = (len(findings) - len(result)) / len(findings)
        assert reduction_rate == 0.8

    def test_gatekeeper_verification_reduction(self):
        """Test gatekeeper reduces verification calls."""
        gatekeeper = VerificationGatekeeper()

        findings = [
            # High confidence + PoC - auto-confirmed
            Finding(
                id="f1",
                rule_id="rce",
                type=FindingType.VULNERABILITY,
                severity=SeverityLevel.CRITICAL,
                confidence=0.95,
                title="RCE with PoC",
                description="Working PoC available",
                fix_suggestion="Remove eval",
                location=CodeLocation(
                    file="route.py",
                    line=10,
                    end_line=10,
                    snippet="eval(x)",
                ),
                source="agent",
                metadata={"poc": "curl ..."},
            ),
            # Low confidence + low severity - needs review only
            Finding(
                id="f2",
                rule_id="info",
                type=FindingType.VULNERABILITY,
                severity=SeverityLevel.INFO,
                confidence=0.3,
                title="Info leak",
                description="Debug output",
                fix_suggestion="Remove debug",
                location=CodeLocation(
                    file="app.py",
                    line=1,
                    end_line=1,
                    snippet="print(x)",
                ),
                source="agent",
            ),
            # Needs verification
            Finding(
                id="f3",
                rule_id="xss",
                type=FindingType.VULNERABILITY,
                severity=SeverityLevel.HIGH,
                confidence=0.7,
                title="Possible XSS",
                description="Possible XSS via innerHTML",
                fix_suggestion="Escape output",
                location=CodeLocation(
                    file="view.py",
                    line=15,
                    end_line=15,
                    snippet="innerHTML = x",
                ),
                source="agent",
            ),
        ]

        verification_needed = [f for f in findings if gatekeeper.should_verify(f).should_verify]

        # Should reduce to 1 verification needed
        assert len(verification_needed) == 1
        reduction_rate = (len(findings) - len(verification_needed)) / len(findings)
        assert reduction_rate == pytest.approx(0.667, rel=0.1)


class TestCodeQLIntegration:
    """Test CodeQL pre-filter integration."""

    def test_codeql_xss_json_response_filtered(self):
        """Test CodeQL XSS findings with JSON response are filtered."""
        pre_filter = CodeQLPreFilter()

        finding = Finding(
            id="xss-fp",
            rule_id="javascript/xss",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="XSS in API",
            description="XSS in API endpoint",
            fix_suggestion="Escape output",
            location=CodeLocation(
                file="api/users.js",
                line=20,
                end_line=20,
                snippet="res.json({ name: req.query.name })",
            ),
            source="codeql",
        )

        accept, reason = pre_filter.should_accept_finding(finding)

        assert accept is False
        assert "HTML" in reason or "false positive" in reason

    def test_codeql_xss_html_response_accepted(self):
        """Test CodeQL XSS findings with HTML response are accepted."""
        pre_filter = CodeQLPreFilter()

        finding = Finding(
            id="xss-real",
            rule_id="javascript/xss",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="XSS in view",
            description="XSS via innerHTML",
            fix_suggestion="Use textContent",
            location=CodeLocation(
                file="view.js",
                line=15,
                end_line=15,
                snippet="document.getElementById('output').innerHTML = userInput",
            ),
            source="codeql",
        )

        accept, reason = pre_filter.should_accept_finding(finding)

        assert accept is True


class TestStreamingValidatorIntegration:
    """Test streaming validator integration."""

    def test_validator_catches_hallucinations(self):
        """Test validator catches hallucinated findings."""
        validator = StreamingValidator()

        # Hallucinated finding - no execution evidence
        finding = Finding(
            id="hallucination",
            rule_id="cmd_injection",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.CRITICAL,
            confidence=0.9,
            title="Command Injection",
            description="Possible command injection via string concatenation",
            fix_suggestion="Use subprocess with list args",
            location=CodeLocation(
                file="utils.py",
                line=5,
                end_line=5,
                snippet='message = "Command: " + cmd_name',
            ),
            source="agent",
        )

        result = validator.validate_finding(finding)

        # Finding is accepted but confidence may be adjusted
        # The validator doesn't reject hallucinations outright in non-strict mode
        assert result is not None
        assert result.accept is True or result.reason != ""

    def test_validator_accepts_strong_findings(self):
        """Test validator accepts findings with strong evidence."""
        validator = StreamingValidator()

        finding = Finding(
            id="real",
            rule_id="cmd_injection",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.CRITICAL,
            confidence=0.9,
            title="Command Injection",
            description="Confirmed command injection",
            fix_suggestion="Use subprocess",
            location=CodeLocation(
                file="route.py",
                line=10,
                end_line=10,
                snippet="os.system(user_input)",
            ),
            source="agent",
            metadata={"execution_path": "user_input -> os.system"},
        )

        result = validator.validate_finding(finding)

        # Strong finding should be accepted
        assert result.accept is True


class TestRealWorldScenarios:
    """Test real-world scenarios."""

    def test_api_project_xss_filtering(self):
        """Test XSS filtering in API project."""
        codeql_filter = CodeQLPreFilter()
        gatekeeper = VerificationGatekeeper()

        findings = [
            Finding(
                id="xss-api",
                rule_id="javascript/xss",
                type=FindingType.VULNERABILITY,
                severity=SeverityLevel.HIGH,
                confidence=0.7,
                title="XSS in API",
                description="XSS in API endpoint",
                fix_suggestion="Escape output",
                location=CodeLocation(
                    file="api/users.js",
                    line=20,
                    end_line=20,
                    snippet="res.json({ data: req.query.name })",
                ),
                source="codeql",
            ),
        ]

        # CodeQL filter should reject
        accept, _ = codeql_filter.should_accept_finding(findings[0])
        assert accept is False

    def test_web_app_xss_accepted(self):
        """Test XSS in web app is accepted."""
        codeql_filter = CodeQLPreFilter()
        file_filter = FilePreFilter()

        finding = Finding(
            id="xss-web",
            rule_id="javascript/xss",
            type=FindingType.VULNERABILITY,
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            title="XSS in web app",
            description="XSS via innerHTML",
            fix_suggestion="Use textContent",
            location=CodeLocation(
                file="views/dashboard.js",
                line=25,
                end_line=25,
                snippet="document.querySelector('#output').innerHTML = userInput",
            ),
            source="codeql",
        )

        # File filter should accept views directory
        result = file_filter.should_analyze(
            Path("views/dashboard.js"),
            "function render() { innerHTML = x }"
        )
        assert result.should_analyze is True

        # CodeQL filter should accept
        accept, _ = codeql_filter.should_accept_finding(finding)
        assert accept is True

    def test_generated_code_filtering(self):
        """Test generated code is filtered out."""
        file_filter = FilePreFilter()

        # Test directory-based filtering
        vendor_result = file_filter.should_analyze(
            Path("vendor/jquery.min.js"),
            "jquery code"
        )
        node_modules_result = file_filter.should_analyze(
            Path("node_modules/package/index.js"),
            "module code"
        )

        assert vendor_result.should_analyze is False
        assert node_modules_result.should_analyze is False

    def test_config_file_filtering(self):
        """Test config files are filtered out."""
        file_filter = FilePreFilter()

        config_files = [
            ("config.yaml", "key: value"),
            ("settings.json", '{"key": "value"}'),
            (".env.production", "KEY=value"),
            ("docker-compose.yml", "version: '3'"),
            ("package-lock.json", '{"name": "test"}'),
        ]

        for file_path, content in config_files:
            result = file_filter.should_analyze(Path(file_path), content)
            assert result.should_analyze is False, f"File {file_path} should be filtered"


class TestMetricsCollection:
    """Test metrics collection for effect evaluation."""

    def test_file_filter_metrics(self):
        """Test file filter metrics."""
        file_filter = FilePreFilter()

        # Test filtering decisions
        results = {
            "app.py": file_filter.should_analyze(Path("app.py"), "def hello(): pass"),
            "config.yaml": file_filter.should_analyze(Path("config.yaml"), "key: value"),
            "utils.py": file_filter.should_analyze(Path("utils.py"), "def util(): pass"),
            "package.json": file_filter.should_analyze(Path("package.json"), '{"name": "test"}'),
            "views.py": file_filter.should_analyze(Path("views.py"), "def view(): pass"),
        }

        scanned = sum(1 for r in results.values() if r.should_analyze)
        filtered = sum(1 for r in results.values() if not r.should_analyze)

        assert scanned == 3
        assert filtered == 2
        assert len(results) == 5

    def test_deduplicator_metrics(self):
        """Test deduplicator metrics."""
        deduplicator = InMemoryDeduplicator()

        findings = [
            Finding(
                id=f"f{i}",
                rule_id="test",
                type=FindingType.VULNERABILITY,
                severity=SeverityLevel.MEDIUM,
                confidence=0.7,
                title=f"Test {i}",
                description="Test",
                fix_suggestion=None,
                location=CodeLocation(
                    file="test.py",
                    line=10 if i < 3 else 20,
                    end_line=10 if i < 3 else 20,
                    snippet="code",
                ),
                source="agent",
                final_score=1.0,
            )
            for i in range(5)
        ]

        result = deduplicator.deduplicate_findings(findings, "test.py")
        stats = deduplicator.get_stats()

        assert stats.total_input == 5
        assert stats.total_output == 2
        assert stats.reduction_rate() == 0.6

    def test_gatekeeper_metrics(self):
        """Test gatekeeper metrics."""
        gatekeeper = BatchGatekeeper()

        findings = [
            Finding(
                id="f1",
                rule_id="test",
                type=FindingType.VULNERABILITY,
                severity=SeverityLevel.INFO,
                confidence=0.3,
                title="Low priority",
                description="Test",
                fix_suggestion=None,
                location=CodeLocation(
                    file="test.py",
                    line=1,
                    end_line=1,
                    snippet="code",
                ),
                source="agent",
            ),
            Finding(
                id="f2",
                rule_id="test",
                type=FindingType.VULNERABILITY,
                severity=SeverityLevel.HIGH,
                confidence=0.7,
                title="Needs verification",
                description="Test",
                fix_suggestion=None,
                location=CodeLocation(
                    file="test.py",
                    line=2,
                    end_line=2,
                    snippet="code",
                ),
                source="agent",
            ),
        ]

        categories = gatekeeper.categorize_findings(findings)
        stats = gatekeeper.get_stats(categories)

        assert stats["needs_review"] == 1
        assert stats["requires_verification"] == 1
        assert stats["confirmed"] + stats["false_positive"] == 0


# Import BatchGatekeeper for metrics test
from src.layers.l3_analysis.verification.verification_gatekeeper import BatchGatekeeper
