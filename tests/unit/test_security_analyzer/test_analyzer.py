"""Tests for security analyzer."""

import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.layers.l1_intelligence.dependency_scanner.base_scanner import (
    Dependency,
    Ecosystem,
)
from src.layers.l1_intelligence.security_analyzer.analyzer import (
    DependencyVuln,
    FrameworkVuln,
    SecurityAnalyzer,
    SecurityReport,
)
from src.layers.l1_intelligence.tech_stack_detector.detector import (
    Framework,
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
    affected_products: list[str] | None = None,
) -> CVEInfo:
    """Helper to create CVEInfo with required fields."""
    return CVEInfo(
        cve_id=cve_id,
        source="nvd",
        description=description,
        severity=severity,
        kev=kev,
        affected_products=affected_products or [],
        published_date=datetime.now(),
    )


class TestDependencyVuln:
    """Tests for DependencyVuln model."""

    def test_create_dependency_vuln(self):
        """Test creating a dependency vulnerability."""
        dep = Dependency(
            name="lodash",
            version="4.17.15",
            ecosystem=Ecosystem.NPM,
            source_file="package.json",
        )
        vuln = DependencyVuln(
            dependency=dep,
            cves=[],
            highest_severity=SeverityLevel.HIGH,
            has_kev=True,
            kev_cves=["CVE-2021-23337"],
        )
        assert vuln.dependency.name == "lodash"
        assert vuln.highest_severity == SeverityLevel.HIGH
        assert vuln.has_kev is True
        assert vuln.cve_count == 0


class TestFrameworkVuln:
    """Tests for FrameworkVuln model."""

    def test_create_framework_vuln(self):
        """Test creating a framework vulnerability."""
        fw = Framework(name="django", category="web", version="3.2.0")
        vuln = FrameworkVuln(
            framework=fw,
            cves=[],
            highest_severity=SeverityLevel.CRITICAL,
            has_kev=False,
        )
        assert vuln.framework.name == "django"
        assert vuln.highest_severity == SeverityLevel.CRITICAL
        assert vuln.cve_count == 0


class TestSecurityReport:
    """Tests for SecurityReport model."""

    def test_empty_report(self):
        """Test empty security report."""
        report = SecurityReport(source_path="/test/path")
        assert report.total_vulnerabilities == 0
        assert report.has_vulnerabilities is False
        assert report.has_critical_or_high is False
        assert report.has_known_exploited is False

    def test_report_with_vulnerabilities(self):
        """Test report with vulnerabilities."""
        report = SecurityReport(
            source_path="/test/path",
            total_vulnerabilities=10,
            critical_count=2,
            high_count=3,
            medium_count=3,
            low_count=2,
            kev_count=1,
        )
        assert report.has_vulnerabilities is True
        assert report.has_critical_or_high is True
        assert report.has_known_exploited is True

    def test_get_summary(self):
        """Test getting report summary."""
        report = SecurityReport(
            source_path="/test/path",
            dependencies_scanned=50,
            frameworks_detected=3,
            total_vulnerabilities=10,
            critical_count=2,
            high_count=3,
            medium_count=3,
            low_count=2,
            kev_count=1,
        )
        summary = report.get_summary()
        assert summary["source"] == "/test/path"
        assert summary["dependencies"] == 50
        assert summary["frameworks"] == 3
        assert summary["vulnerabilities"] == 10
        assert summary["critical"] == 2
        assert summary["kev"] == 1


class TestSecurityAnalyzer:
    """Tests for SecurityAnalyzer."""

    @pytest.fixture
    def mock_intel_service(self):
        """Create mock intel service."""
        service = MagicMock()
        service.search_cves = AsyncMock(
            return_value=[
                make_cve_info(
                    cve_id="CVE-2021-23337",
                    description="Lodash command injection",
                    severity=SeverityLevel.HIGH,
                    kev=True,
                    affected_products=["lodash"],
                )
            ]
        )
        return service

    @pytest.fixture
    def analyzer(self, mock_intel_service):
        """Create analyzer instance."""
        return SecurityAnalyzer(intel_service=mock_intel_service)

    def test_create_analyzer(self, mock_intel_service):
        """Test creating analyzer."""
        analyzer = SecurityAnalyzer(intel_service=mock_intel_service)
        assert analyzer.intel_service is not None
        assert analyzer.npm_scanner is not None
        assert analyzer.python_scanner is not None
        assert analyzer.tech_detector is not None

    @pytest.mark.asyncio
    async def test_analyze_empty_directory(self, mock_intel_service):
        """Test analyzing empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            analyzer = SecurityAnalyzer(intel_service=mock_intel_service)
            report = await analyzer.analyze(path)

            assert report.source_path == str(path)
            assert report.dependencies_scanned == 0
            assert report.total_vulnerabilities == 0

    @pytest.mark.asyncio
    async def test_analyze_python_project(self, mock_intel_service):
        """Test analyzing Python project with vulnerabilities."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            # Create requirements.txt with a known vulnerable package
            (path / "requirements.txt").write_text("lodash==4.17.15")

            # Mock CVE search to return relevant results
            mock_intel_service.search_cves = AsyncMock(
                return_value=[
                    make_cve_info(
                        cve_id="CVE-2021-23337",
                        description="lodash command injection vulnerability",
                        severity=SeverityLevel.HIGH,
                        kev=True,
                        affected_products=["lodash"],
                    )
                ]
            )

            analyzer = SecurityAnalyzer(intel_service=mock_intel_service)
            report = await analyzer.analyze(path)

            assert report.dependencies_scanned >= 1

    def test_filter_relevant_cves(self, mock_intel_service):
        """Test filtering relevant CVEs."""
        analyzer = SecurityAnalyzer(intel_service=mock_intel_service)
        dep = Dependency(
            name="lodash",
            version="4.17.15",
            ecosystem=Ecosystem.NPM,
            source_file="package.json",
        )
        cves = [
            make_cve_info(
                cve_id="CVE-2021-23337",
                description="lodash command injection",
                severity=SeverityLevel.HIGH,
                kev=True,
                affected_products=["lodash"],
            ),
            make_cve_info(
                cve_id="CVE-2022-12345",
                description="Some other vulnerability",
                severity=SeverityLevel.MEDIUM,
                kev=False,
                affected_products=["other-package"],
            ),
        ]

        relevant = analyzer._filter_relevant_cves(cves, dep)
        assert len(relevant) == 1
        assert relevant[0].cve_id == "CVE-2021-23337"

    def test_get_highest_severity(self, mock_intel_service):
        """Test getting highest severity."""
        analyzer = SecurityAnalyzer(intel_service=mock_intel_service)
        cves = [
            make_cve_info(
                cve_id="CVE-1",
                description="Low",
                severity=SeverityLevel.LOW,
                kev=False,
            ),
            make_cve_info(
                cve_id="CVE-2",
                description="Critical",
                severity=SeverityLevel.CRITICAL,
                kev=False,
            ),
            make_cve_info(
                cve_id="CVE-3",
                description="Medium",
                severity=SeverityLevel.MEDIUM,
                kev=False,
            ),
        ]

        highest = analyzer._get_highest_severity(cves)
        assert highest == SeverityLevel.CRITICAL

    def test_get_highest_severity_empty(self, mock_intel_service):
        """Test getting highest severity with empty list."""
        analyzer = SecurityAnalyzer(intel_service=mock_intel_service)
        highest = analyzer._get_highest_severity([])
        assert highest == SeverityLevel.INFO

    def test_calculate_statistics(self, mock_intel_service):
        """Test calculating statistics."""
        analyzer = SecurityAnalyzer(intel_service=mock_intel_service)
        report = SecurityReport(source_path="/test")
        report.dependency_vulns = [
            DependencyVuln(
                dependency=Dependency(
                    name="pkg1",
                    version="1.0.0",
                    ecosystem=Ecosystem.NPM,
                    source_file="package.json",
                ),
                cves=[
                    make_cve_info(
                        cve_id="CVE-1",
                        description="Critical",
                        severity=SeverityLevel.CRITICAL,
                        kev=True,
                    ),
                    make_cve_info(
                        cve_id="CVE-2",
                        description="High",
                        severity=SeverityLevel.HIGH,
                        kev=False,
                    ),
                ],
                highest_severity=SeverityLevel.CRITICAL,
                has_kev=True,
                kev_cves=["CVE-1"],
            )
        ]
        report.framework_vulns = [
            FrameworkVuln(
                framework=Framework(name="django", category="web"),
                cves=[
                    make_cve_info(
                        cve_id="CVE-3",
                        description="Medium",
                        severity=SeverityLevel.MEDIUM,
                        kev=False,
                    ),
                ],
                highest_severity=SeverityLevel.MEDIUM,
                has_kev=False,
            )
        ]

        analyzer._calculate_statistics(report)

        assert report.total_vulnerabilities == 3
        assert report.critical_count == 1
        assert report.high_count == 1
        assert report.medium_count == 1
        assert report.low_count == 0
        assert report.kev_count == 1
        assert "pkg1" in report.kev_packages

    @pytest.mark.asyncio
    async def test_analyze_without_intel_service(self):
        """Test analyzing without intel service."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "requirements.txt").write_text("requests==2.28.0")

            analyzer = SecurityAnalyzer(intel_service=None)
            report = await analyzer.analyze(path)

            # Should still scan dependencies but skip CVE lookup
            assert report.dependencies_scanned >= 1
            assert len(report.dependency_vulns) == 0
