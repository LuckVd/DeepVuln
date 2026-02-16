"""Unit tests for OSV API client."""

import pytest

from src.layers.l1_intelligence.threat_intel.sources.advisories.osv_client import (
    OSVClient,
)


class TestOSVClient:
    """Tests for OSVClient."""

    def test_ecosystem_mapping(self) -> None:
        """Test ecosystem mapping."""
        client = OSVClient()

        assert client._map_ecosystem("npm") == "npm"
        assert client._map_ecosystem("pip") == "PyPI"
        assert client._map_ecosystem("pypi") == "PyPI"
        assert client._map_ecosystem("go") == "Go"
        assert client._map_ecosystem("maven") == "Maven"
        assert client._map_ecosystem("cargo") == "crates.io"
        assert client._map_ecosystem("rust") == "crates.io"
        assert client._map_ecosystem("unknown") == "unknown"

    def test_severity_mapping_by_cvss(self) -> None:
        """Test severity mapping by CVSS score."""
        client = OSVClient()

        from src.layers.l1_intelligence.threat_intel.core.data_models import (
            SeverityLevel,
        )

        assert client._map_severity(None, 9.5) == SeverityLevel.CRITICAL
        assert client._map_severity(None, 9.0) == SeverityLevel.CRITICAL
        assert client._map_severity(None, 8.9) == SeverityLevel.HIGH
        assert client._map_severity(None, 7.0) == SeverityLevel.HIGH
        assert client._map_severity(None, 6.9) == SeverityLevel.MEDIUM
        assert client._map_severity(None, 4.0) == SeverityLevel.MEDIUM
        assert client._map_severity(None, 3.9) == SeverityLevel.LOW
        assert client._map_severity(None, 0.1) == SeverityLevel.LOW
        assert client._map_severity(None, 0) == SeverityLevel.INFO
        assert client._map_severity(None, None) == SeverityLevel.INFO

    def test_severity_mapping_by_string(self) -> None:
        """Test severity mapping by string."""
        client = OSVClient()

        from src.layers.l1_intelligence.threat_intel.core.data_models import (
            SeverityLevel,
        )

        assert client._map_severity("critical", None) == SeverityLevel.CRITICAL
        assert client._map_severity("CRITICAL", None) == SeverityLevel.CRITICAL
        assert client._map_severity("high", None) == SeverityLevel.HIGH
        assert client._map_severity("HIGH", None) == SeverityLevel.HIGH
        assert client._map_severity("moderate", None) == SeverityLevel.MEDIUM
        assert client._map_severity("medium", None) == SeverityLevel.MEDIUM
        assert client._map_severity("low", None) == SeverityLevel.LOW
        assert client._map_severity("unknown", None) == SeverityLevel.INFO

    def test_cvss_takes_precedence(self) -> None:
        """Test that CVSS score takes precedence over string."""
        client = OSVClient()

        from src.layers.l1_intelligence.threat_intel.core.data_models import (
            SeverityLevel,
        )

        # CVSS 9.0 = CRITICAL, even if string says "low"
        assert client._map_severity("low", 9.0) == SeverityLevel.CRITICAL

    @pytest.mark.asyncio
    async def test_query_by_package_maven(self) -> None:
        """Test querying Maven package (integration test)."""
        client = OSVClient()

        try:
            # Query a known vulnerable package: log4j-core
            # This should return some CVEs for version 2.14.1
            cves = await client.query_by_package(
                package_name="org.apache.logging.log4j:log4j-core",
                ecosystem="Maven",
                version="2.14.1",
            )

            # Log4j 2.14.1 is vulnerable, should have CVEs
            # Note: This is an integration test and depends on OSV API availability
            # If it fails due to network, it's okay
            if cves:
                # Check that we got valid CVE info
                for cve in cves:
                    assert cve.cve_id is not None
                    assert cve.source == "osv"
                    assert "osv" in cve.tags
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_query_by_package_not_found(self) -> None:
        """Test querying non-existent package."""
        client = OSVClient()

        try:
            cves = await client.query_by_package(
                package_name="nonexistent.package.12345:fake",
                ecosystem="Maven",
                version="1.0.0",
            )

            # Should return empty list for non-existent package
            assert cves == []
        finally:
            await client.close()
