"""Tests for threat intelligence data models."""

from datetime import datetime

from src.layers.l1_intelligence.threat_intel.core.data_models import (
    CVEInfo,
    PoCInfo,
    SearchResult,
    SeverityLevel,
    SyncStatus,
    ThreatIntel,
)


class TestCVEInfo:
    """Tests for CVEInfo model."""

    def test_create_cve_info(self) -> None:
        """Test creating a CVEInfo instance."""
        cve = CVEInfo(
            cve_id="CVE-2024-1234",
            source="nvd",
            description="Test vulnerability",
            severity=SeverityLevel.HIGH,
            cvss_v3_score=7.5,
            published_date=datetime.now(),
        )

        assert cve.cve_id == "CVE-2024-1234"
        assert cve.source == "nvd"
        assert cve.severity == SeverityLevel.HIGH
        assert cve.cvss_v3_score == 7.5
        assert cve.kev is False
        assert cve.has_poc is False

    def test_cve_info_defaults(self) -> None:
        """Test CVEInfo default values."""
        cve = CVEInfo(
            cve_id="CVE-2024-0001",
            source="test",
            description="Test",
            severity=SeverityLevel.INFO,
            published_date=datetime.now(),
        )

        assert cve.cwe_ids == []
        assert cve.references == []
        assert cve.tags == []
        assert cve.affected_products == []

    def test_cve_info_with_kev(self) -> None:
        """Test CVEInfo with KEV flag."""
        cve = CVEInfo(
            cve_id="CVE-2024-21762",
            source="nvd",
            description="Out-of-bounds write",
            severity=SeverityLevel.CRITICAL,
            cvss_v3_score=9.8,
            kev=True,
            ransomware_use=True,
            published_date=datetime.now(),
        )

        assert cve.kev is True
        assert cve.ransomware_use is True


class TestPoCInfo:
    """Tests for PoCInfo model."""

    def test_create_poc_info(self) -> None:
        """Test creating a PoCInfo instance."""
        poc = PoCInfo(
            poc_id="EDB-12345",
            source="exploitdb",
            title="Test Exploit",
            cve_ids=["CVE-2024-1234"],
            code_url="https://example.com/poc",
        )

        assert poc.poc_id == "EDB-12345"
        assert poc.source == "exploitdb"
        assert poc.cve_ids == ["CVE-2024-1234"]
        assert poc.verified is False
        assert poc.dangerous is False

    def test_poc_info_defaults(self) -> None:
        """Test PoCInfo default values."""
        poc = PoCInfo(
            poc_id="test-001",
            source="github",
            title="Test PoC",
        )

        assert poc.cve_ids == []
        assert poc.verified is False
        assert poc.stars == 0


class TestSeverityLevel:
    """Tests for SeverityLevel enum."""

    def test_severity_levels(self) -> None:
        """Test all severity levels exist."""
        assert SeverityLevel.CRITICAL.value == "critical"
        assert SeverityLevel.HIGH.value == "high"
        assert SeverityLevel.MEDIUM.value == "medium"
        assert SeverityLevel.LOW.value == "low"
        assert SeverityLevel.INFO.value == "info"


class TestSyncStatus:
    """Tests for SyncStatus enum."""

    def test_sync_statuses(self) -> None:
        """Test all sync statuses exist."""
        assert SyncStatus.PENDING.value == "pending"
        assert SyncStatus.RUNNING.value == "running"
        assert SyncStatus.SUCCESS.value == "success"
        assert SyncStatus.FAILED.value == "failed"


class TestSearchResult:
    """Tests for SearchResult model."""

    def test_create_search_result(self) -> None:
        """Test creating a SearchResult instance."""
        result = SearchResult(
            query="apache struts",
            source="google",
            title="Apache Struts Vulnerability",
            url="https://example.com/article",
            snippet="Critical vulnerability in Apache Struts...",
        )

        assert result.query == "apache struts"
        assert result.source == "google"
        assert result.related_cves == []


class TestThreatIntel:
    """Tests for ThreatIntel model."""

    def test_create_threat_intel(self) -> None:
        """Test creating a ThreatIntel instance."""
        intel = ThreatIntel(
            intel_id="TI-001",
            source="misp",
            intel_type="apt",
            title="APT Group Activity",
            description="Observed APT group targeting...",
            created_date=datetime.now(),
        )

        assert intel.intel_id == "TI-001"
        assert intel.intel_type == "apt"
        assert intel.confidence == 50
        assert intel.iocs == []
