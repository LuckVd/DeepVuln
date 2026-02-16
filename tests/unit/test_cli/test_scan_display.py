"""Tests for CLI scan display components."""

from datetime import datetime

from src.cli.scan_display import (
    export_report_text,
    show_quick_scan_result,
    show_severity_breakdown,
    show_security_summary,
    show_tech_stack,
    show_vulnerability_list,
)
from src.layers.l1_intelligence.dependency_scanner.base_scanner import (
    Dependency,
    Ecosystem,
)
from src.layers.l1_intelligence.security_analyzer.analyzer import (
    DependencyVuln,
    FrameworkVuln,
    SecurityReport,
)
from src.layers.l1_intelligence.tech_stack_detector.detector import (
    Framework,
    Language,
    TechStack,
)
from src.layers.l1_intelligence.threat_intel.core.data_models import (
    CVEInfo,
    SeverityLevel,
)


def make_cve_info(
    cve_id: str,
    description: str,
    severity: SeverityLevel,
    kev: bool = False,
) -> CVEInfo:
    """Helper to create CVEInfo."""
    return CVEInfo(
        cve_id=cve_id,
        source="nvd",
        description=description,
        severity=severity,
        kev=kev,
        published_date=datetime.now(),
    )


class TestShowSecuritySummary:
    """Tests for show_security_summary."""

    def test_show_summary_no_issues(self, capsys):
        """Test showing summary with no issues."""
        report = SecurityReport(
            source_path="/test/path",
            dependencies_scanned=10,
            frameworks_detected=2,
            total_vulnerabilities=0,
        )
        show_security_summary(report)
        # Should not raise any errors

    def test_show_summary_with_issues(self, capsys):
        """Test showing summary with issues."""
        report = SecurityReport(
            source_path="/test/path",
            dependencies_scanned=10,
            frameworks_detected=2,
            total_vulnerabilities=5,
            critical_count=1,
            high_count=2,
            kev_count=1,
        )
        show_security_summary(report)
        # Should not raise any errors


class TestShowSeverityBreakdown:
    """Tests for show_severity_breakdown."""

    def test_show_breakdown_empty(self):
        """Test showing breakdown with no vulnerabilities."""
        report = SecurityReport(source_path="/test")
        show_severity_breakdown(report)
        # Should not raise any errors

    def test_show_breakdown_with_vulns(self):
        """Test showing breakdown with vulnerabilities."""
        report = SecurityReport(
            source_path="/test",
            total_vulnerabilities=10,
            critical_count=2,
            high_count=3,
            medium_count=3,
            low_count=2,
        )
        show_severity_breakdown(report)
        # Should not raise any errors


class TestShowVulnerabilityList:
    """Tests for show_vulnerability_list."""

    def test_show_list_empty(self):
        """Test showing empty vulnerability list."""
        report = SecurityReport(source_path="/test")
        show_vulnerability_list(report)
        # Should not raise any errors

    def test_show_list_with_vulns(self):
        """Test showing vulnerability list."""
        report = SecurityReport(
            source_path="/test",
            total_vulnerabilities=2,
        )
        report.dependency_vulns = [
            DependencyVuln(
                dependency=Dependency(
                    name="lodash",
                    version="4.17.15",
                    ecosystem=Ecosystem.NPM,
                    source_file="package.json",
                ),
                cves=[
                    make_cve_info(
                        "CVE-2021-23337",
                        "Command injection",
                        SeverityLevel.HIGH,
                        kev=True,
                    ),
                ],
                highest_severity=SeverityLevel.HIGH,
                has_kev=True,
                kev_cves=["CVE-2021-23337"],
            )
        ]
        show_vulnerability_list(report, show_all=True)
        # Should not raise any errors


class TestShowTechStack:
    """Tests for show_tech_stack."""

    def test_show_tech_stack_empty(self):
        """Test showing empty tech stack."""
        tech_stack = TechStack()
        show_tech_stack(tech_stack)
        # Should not raise any errors

    def test_show_tech_stack_full(self):
        """Test showing full tech stack."""
        tech_stack = TechStack(
            languages=[Language.PYTHON, Language.JAVASCRIPT],
            frameworks=[
                Framework(name="django", category="web", confidence=0.9),
            ],
        )
        show_tech_stack(tech_stack)
        # Should not raise any errors


class TestShowQuickScanResult:
    """Tests for show_quick_scan_result."""

    def test_show_quick_result_success(self):
        """Test showing successful quick scan result."""
        result = {
            "success": True,
            "dependencies": 10,
            "frameworks": 2,
            "critical_high": 0,
            "kev_count": 0,
            "needs_attention": False,
            "duration": 1.5,
        }
        show_quick_scan_result(result)
        # Should not raise any errors

    def test_show_quick_result_with_issues(self):
        """Test showing quick scan result with issues."""
        result = {
            "success": True,
            "dependencies": 10,
            "frameworks": 2,
            "critical_high": 3,
            "kev_count": 1,
            "needs_attention": True,
            "duration": 2.0,
        }
        show_quick_scan_result(result)
        # Should not raise any errors

    def test_show_quick_result_failed(self):
        """Test showing failed quick scan result."""
        result = {
            "success": False,
            "errors": ["Test error"],
        }
        show_quick_scan_result(result)
        # Should not raise any errors


class TestExportReportText:
    """Tests for export_report_text."""

    def test_export_empty_report(self):
        """Test exporting empty report."""
        report = SecurityReport(source_path="/test/path")
        text = export_report_text(report)

        assert "DeepVuln Security Report" in text
        assert "/test/path" in text
        assert "Total vulnerabilities: 0" in text

    def test_export_report_with_vulns(self):
        """Test exporting report with vulnerabilities."""
        report = SecurityReport(
            source_path="/test/path",
            dependencies_scanned=10,
            total_vulnerabilities=2,
            critical_count=1,
            high_count=1,
            kev_count=1,
        )
        report.dependency_vulns = [
            DependencyVuln(
                dependency=Dependency(
                    name="lodash",
                    version="4.17.15",
                    ecosystem=Ecosystem.NPM,
                    source_file="package.json",
                ),
                cves=[
                    make_cve_info("CVE-2021-23337", "Test vuln", SeverityLevel.HIGH),
                ],
                highest_severity=SeverityLevel.HIGH,
                has_kev=True,
                kev_cves=["CVE-2021-23337"],
            )
        ]

        text = export_report_text(report)

        assert "DeepVuln Security Report" in text
        assert "Critical: 1" in text
        assert "lodash@4.17.15" in text
        assert "CVE-2021-23337" in text

    def test_export_report_with_tech_stack(self):
        """Test exporting report with tech stack."""
        report = SecurityReport(source_path="/test/path")
        report.tech_stack = TechStack(
            languages=[Language.PYTHON],
            frameworks=[Framework(name="django", category="web", confidence=0.9)],
        )

        text = export_report_text(report)

        assert "Technology Stack" in text
        assert "python" in text.lower()
        assert "django" in text.lower()
