"""Integration tests for threat intelligence module."""

from datetime import datetime
from pathlib import Path

import pytest

from src.layers.l1_intelligence.threat_intel.core.data_models import (
    CVEInfo,
    PoCInfo,
    SeverityLevel,
)
from src.layers.l1_intelligence.threat_intel.sources.vulnerabilities.cisa_kev import (
    CISAKEVClient,
)
from src.layers.l1_intelligence.threat_intel.storage.database import ThreatIntelDatabase
from src.layers.l1_intelligence.threat_intel.storage.file_cache import CVECache, FileCache

# Mark all tests as integration
pytestmark = pytest.mark.integration


class TestCISAKEVIntegration:
    """Integration tests for CISA KEV client."""

    @pytest.fixture
    def kev_client(self) -> CISAKEVClient:
        """Create KEV client."""
        return CISAKEVClient()

    @pytest.mark.asyncio
    async def test_sync_kev_catalog(self, kev_client: CISAKEVClient) -> None:
        """Test syncing KEV catalog from CISA."""
        count = await kev_client.sync()

        # Should have synced entries
        assert count > 1000  # KEV typically has 1000+ entries

        # Cache should be populated
        assert kev_client.cache_size == count

    @pytest.mark.asyncio
    async def test_is_kev(self, kev_client: CISAKEVClient) -> None:
        """Test KEV lookup."""
        await kev_client.sync()

        # Check a known KEV CVE
        # Note: This CVE should be in KEV catalog
        kev_cves = kev_client.get_all_kev_cves()
        assert len(kev_cves) > 0

        # Test is_kev method
        test_cve = kev_cves[0]
        assert kev_client.is_kev(test_cve) is True

    @pytest.mark.asyncio
    async def test_enrich_cve(self, kev_client: CISAKEVClient) -> None:
        """Test CVE enrichment with KEV data."""
        await kev_client.sync()

        # Get a KEV CVE
        kev_cves = kev_client.get_all_kev_cves()
        if not kev_cves:
            pytest.skip("No KEV CVEs available")

        test_cve_id = kev_cves[0]

        # Create a CVEInfo
        cve = CVEInfo(
            cve_id=test_cve_id,
            source="test",
            description="Test CVE",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(),
        )

        # Enrich
        enriched = kev_client.enrich_cve(cve)

        # Should be marked as KEV
        assert enriched.kev is True
        assert "known-exploited" in enriched.tags


class TestDatabaseIntegration:
    """Integration tests for database storage."""

    @pytest.fixture
    def db_path(self, tmp_path: Path) -> Path:
        """Create temporary database path."""
        return tmp_path / "test_threat_intel.db"

    @pytest.mark.asyncio
    async def test_save_and_get_cve(self, db_path: Path) -> None:
        """Test saving and retrieving a CVE."""
        async with ThreatIntelDatabase(str(db_path)) as db:
            cve = CVEInfo(
                cve_id="CVE-2024-TEST01",
                source="test",
                description="Test vulnerability for integration testing",
                severity=SeverityLevel.CRITICAL,
                cvss_v3_score=9.8,
                kev=True,
                published_date=datetime.now(),
            )

            # Save
            result = await db.save_cve(cve)
            assert result is True

            # Retrieve
            retrieved = await db.get_cve("CVE-2024-TEST01")
            assert retrieved is not None
            assert retrieved.cve_id == "CVE-2024-TEST01"
            assert retrieved.severity == SeverityLevel.CRITICAL
            assert retrieved.kev is True

    @pytest.mark.asyncio
    async def test_save_and_get_poc(self, db_path: Path) -> None:
        """Test saving and retrieving a PoC."""
        async with ThreatIntelDatabase(str(db_path)) as db:
            # Save the CVE first for mapping
            cve = CVEInfo(
                cve_id="CVE-2024-TEST01",
                source="test",
                description="Test",
                severity=SeverityLevel.HIGH,
                published_date=datetime.now(),
            )
            await db.save_cve(cve)

            poc = PoCInfo(
                poc_id="TEST-001",
                source="test",
                title="Test Exploit",
                cve_ids=["CVE-2024-TEST01"],
                verified=True,
            )

            # Save
            result = await db.save_poc(poc)
            assert result is True

            # Retrieve PoCs for CVE
            pocs = await db.get_pocs_for_cve("CVE-2024-TEST01")
            assert len(pocs) == 1
            assert pocs[0].poc_id == "TEST-001"

    @pytest.mark.asyncio
    async def test_search_cves(self, db_path: Path) -> None:
        """Test CVE search functionality."""
        async with ThreatIntelDatabase(str(db_path)) as db:
            # Save some test CVEs
            for i in range(5):
                cve = CVEInfo(
                    cve_id=f"CVE-2024-TEST{i:02d}",
                    source="test",
                    description=f"Test vulnerability {i} with unique keyword xyz{i}",
                    severity=SeverityLevel.HIGH,
                    published_date=datetime.now(),
                )
                await db.save_cve(cve)

            # Search
            results = await db.search_cves("xyz", limit=10)

            # Should find our test CVEs
            assert len(results) >= 1

    @pytest.mark.asyncio
    async def test_get_kev_cves(self, db_path: Path) -> None:
        """Test getting KEV CVEs."""
        async with ThreatIntelDatabase(str(db_path)) as db:
            # Save KEV and non-KEV CVEs
            kev_cve = CVEInfo(
                cve_id="CVE-2024-KEV01",
                source="test",
                description="KEV test",
                severity=SeverityLevel.CRITICAL,
                kev=True,
                published_date=datetime.now(),
            )
            normal_cve = CVEInfo(
                cve_id="CVE-2024-NORMAL01",
                source="test",
                description="Normal test",
                severity=SeverityLevel.HIGH,
                kev=False,
                published_date=datetime.now(),
            )

            await db.save_cve(kev_cve)
            await db.save_cve(normal_cve)

            # Get KEV CVEs
            kev_cves = await db.get_kev_cves(limit=100)

            # Should include our KEV CVE
            kev_ids = [c.cve_id for c in kev_cves]
            assert "CVE-2024-KEV01" in kev_ids
            assert "CVE-2024-NORMAL01" not in kev_ids

    @pytest.mark.asyncio
    async def test_get_stats(self, db_path: Path) -> None:
        """Test database statistics."""
        async with ThreatIntelDatabase(str(db_path)) as db:
            # Save some CVEs
            for i in range(3):
                cve = CVEInfo(
                    cve_id=f"CVE-2024-STAT{i:02d}",
                    source="test",
                    description=f"Stats test {i}",
                    severity=SeverityLevel.HIGH,
                    published_date=datetime.now(),
                )
                await db.save_cve(cve)

            stats = await db.get_stats()

            assert stats["total_cves"] >= 3
            assert "severity_distribution" in stats


class TestCacheIntegration:
    """Integration tests for file cache."""

    @pytest.fixture
    def cache(self, tmp_path: Path) -> FileCache:
        """Create temporary cache."""
        cache_dir = tmp_path / "cache"
        return FileCache(str(cache_dir), default_ttl=60)

    @pytest.mark.asyncio
    async def test_set_and_get(self, cache: FileCache) -> None:
        """Test setting and getting cache values."""
        key = "test_key"
        value = {"data": "test_value", "number": 42}

        # Set
        result = await cache.set(key, value)
        assert result is True

        # Get
        retrieved = await cache.get(key)
        assert retrieved == value

    @pytest.mark.asyncio
    async def test_cache_miss(self, cache: FileCache) -> None:
        """Test cache miss."""
        result = await cache.get("nonexistent_key")
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_delete(self, cache: FileCache) -> None:
        """Test cache deletion."""
        key = "delete_test"
        value = {"test": "data"}

        await cache.set(key, value)
        assert await cache.get(key) is not None

        await cache.delete(key)
        assert await cache.get(key) is None

    @pytest.mark.asyncio
    async def test_get_or_set(self, cache: FileCache) -> None:
        """Test get_or_set functionality."""
        key = "compute_test"
        call_count = 0

        async def factory():
            nonlocal call_count
            call_count += 1
            return {"computed": True, "call": call_count}

        # First call should compute
        result1 = await cache.get_or_set(key, factory)
        assert result1["computed"] is True
        assert call_count == 1

        # Second call should use cache
        result2 = await cache.get_or_set(key, factory)
        assert result2 == result1
        assert call_count == 1  # Not incremented


class TestCVECache:
    """Integration tests for CVE cache."""

    @pytest.fixture
    def cve_cache(self, tmp_path: Path) -> CVECache:
        """Create CVE cache."""
        cache_dir = tmp_path / "cve_cache"
        return CVECache(str(cache_dir))

    @pytest.mark.asyncio
    async def test_cve_cache_operations(self, cve_cache: CVECache) -> None:
        """Test CVE-specific cache operations."""
        cve_id = "CVE-2024-CACHE01"
        cve_data = {
            "cve_id": cve_id,
            "description": "Test CVE for caching",
            "severity": "high",
        }

        # Cache CVE
        result = await cve_cache.set_cve(cve_id, cve_data)
        assert result is True

        # Retrieve CVE
        retrieved = await cve_cache.get_cve(cve_id)
        assert retrieved == cve_data
