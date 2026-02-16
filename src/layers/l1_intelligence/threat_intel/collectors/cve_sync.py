"""CVE synchronization service - integrates NVD and KEV data."""

from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.threat_intel.core.data_models import (
    CVEInfo,
    SyncRecord,
    SyncStatus,
)
from src.layers.l1_intelligence.threat_intel.sources.vulnerabilities.cisa_kev import (
    CISAKEVClient,
)
from src.layers.l1_intelligence.threat_intel.sources.vulnerabilities.nvd_client import (
    NVDClient,
)

logger = get_logger(__name__)


class CVESyncService:
    """CVE synchronization service.

    Orchestrates CVE data collection from multiple sources:
    - NVD (National Vulnerability Database)
    - CISA KEV (Known Exploited Vulnerabilities)
    """

    def __init__(
        self,
        nvd_api_key: str | None = None,
    ) -> None:
        """Initialize CVE sync service.

        Args:
            nvd_api_key: NVD API key for higher rate limits.
        """
        self.nvd = NVDClient(api_key=nvd_api_key)
        self.kev = CISAKEVClient()
        self._sync_records: dict[str, SyncRecord] = {}

    async def __aenter__(self) -> "CVESyncService":
        """Enter async context."""
        await self.nvd.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context."""
        await self.nvd.close()

    async def sync_kev(self) -> SyncRecord:
        """Sync CISA KEV catalog.

        Returns:
            SyncRecord with sync status.
        """
        record = SyncRecord(
            source="cisa_kev",
            sync_type="full",
            status=SyncStatus.RUNNING,
            started_at=datetime.now(),
        )

        try:
            count = await self.kev.sync()
            record.status = SyncStatus.SUCCESS
            record.records_fetched = count
            record.completed_at = datetime.now()
            record.duration_seconds = (
                record.completed_at - record.started_at
            ).total_seconds()

            logger.info(f"KEV sync complete: {count} entries")

        except Exception as e:
            record.status = SyncStatus.FAILED
            record.error_message = str(e)
            record.completed_at = datetime.now()
            logger.error(f"KEV sync failed: {e}")

        self._sync_records["cisa_kev"] = record
        return record

    async def sync_recent_cves(
        self,
        days: int = 7,
        include_kev: bool = True,
    ) -> AsyncIterator[CVEInfo]:
        """Sync CVEs published in recent days.

        Args:
            days: Number of days to look back.
            include_kev: Whether to enrich with KEV data.

        Yields:
            CVEInfo objects.
        """
        start_date = datetime.now() - timedelta(days=days)

        logger.info(f"Syncing CVEs from {start_date.date()}")

        # Ensure KEV is synced for enrichment
        if include_kev and self.kev.cache_size == 0:
            await self.sync_kev()

        async for cve in self.nvd.get_cves_by_date(start_date):
            if include_kev:
                cve = self.kev.enrich_cve(cve)
            yield cve

    async def sync_modified_cves(
        self,
        since: datetime,
        include_kev: bool = True,
    ) -> AsyncIterator[CVEInfo]:
        """Sync CVEs modified since a given date.

        Args:
            since: Last sync timestamp.
            include_kev: Whether to enrich with KEV data.

        Yields:
            CVEInfo objects.
        """
        logger.info(f"Syncing CVEs modified since {since}")

        if include_kev and self.kev.cache_size == 0:
            await self.sync_kev()

        async for cve in self.nvd.get_cves_modified_since(since):
            if include_kev:
                cve = self.kev.enrich_cve(cve)
            yield cve

    async def get_cve(self, cve_id: str, include_kev: bool = True) -> CVEInfo | None:
        """Get a single CVE by ID.

        Args:
            cve_id: CVE identifier.
            include_kev: Whether to enrich with KEV data.

        Returns:
            CVEInfo or None.
        """
        cve = await self.nvd.get_cve(cve_id)

        if cve and include_kev:
            cve = self.kev.enrich_cve(cve)

        return cve

    async def search_cves(self, query: str) -> AsyncIterator[CVEInfo]:
        """Search CVEs by keyword.

        Args:
            query: Search keyword.

        Yields:
            CVEInfo objects.
        """
        async for cve in self.nvd.search(query):
            yield self.kev.enrich_cve(cve)

    async def full_sync(
        self,
        days: int = 30,
        batch_callback: Any = None,
    ) -> dict[str, Any]:
        """Perform a full sync of all sources.

        Args:
            days: Days of CVEs to sync.
            batch_callback: Optional callback for each batch.

        Returns:
            Sync statistics.
        """
        stats = {
            "started_at": datetime.now(),
            "kev_synced": 0,
            "cves_synced": 0,
            "errors": [],
        }

        try:
            # Sync KEV first
            kev_record = await self.sync_kev()
            stats["kev_synced"] = kev_record.records_fetched

            if kev_record.status == SyncStatus.FAILED:
                stats["errors"].append(f"KEV sync failed: {kev_record.error_message}")

            # Sync recent CVEs
            batch_size = 0
            async for _cve in self.sync_recent_cves(days):
                stats["cves_synced"] += 1
                batch_size += 1

                if batch_callback and batch_size >= 100:
                    await batch_callback(stats)
                    batch_size = 0

        except Exception as e:
            stats["errors"].append(str(e))
            logger.error(f"Full sync error: {e}")

        stats["completed_at"] = datetime.now()
        stats["duration_seconds"] = (
            stats["completed_at"] - stats["started_at"]
        ).total_seconds()

        return stats

    def get_sync_record(self, source: str) -> SyncRecord | None:
        """Get sync record for a source.

        Args:
            source: Source name.

        Returns:
            SyncRecord or None.
        """
        return self._sync_records.get(source)

    def get_all_sync_records(self) -> dict[str, SyncRecord]:
        """Get all sync records.

        Returns:
            Dictionary of sync records.
        """
        return self._sync_records.copy()

    @property
    def kev_count(self) -> int:
        """Get number of KEV entries."""
        return self.kev.cache_size
