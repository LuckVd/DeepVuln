"""Unified threat intelligence service - main entry point."""

from datetime import datetime
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.threat_intel.collectors.cve_sync import CVESyncService
from src.layers.l1_intelligence.threat_intel.core.data_models import (
    CVEInfo,
    PoCInfo,
    ThreatIntelConfig,
)
from src.layers.l1_intelligence.threat_intel.scheduler.sync_scheduler import (
    IntelSyncScheduler,
)
from src.layers.l1_intelligence.threat_intel.sources.pocs.exploitdb_client import (
    ExploitDBClient,
)
from src.layers.l1_intelligence.threat_intel.sources.pocs.github_search import (
    GitHubPoCSearcher,
)
from src.layers.l1_intelligence.threat_intel.storage.database import ThreatIntelDatabase

logger = get_logger(__name__)


class IntelService:
    """Unified threat intelligence service.

    Provides a single entry point for all threat intelligence operations:
    - CVE queries and search
    - PoC/exploit lookup
    - Synchronization management
    - Database operations
    """

    def __init__(
        self,
        db_path: str = "./data/threat_intel.db",
        nvd_api_key: str | None = None,
        github_token: str | None = None,
        config: ThreatIntelConfig | None = None,
    ) -> None:
        """Initialize threat intelligence service.

        Args:
            db_path: Path to SQLite database.
            nvd_api_key: NVD API key for higher rate limits.
            github_token: GitHub token for API access.
            config: Optional configuration object.
        """
        self.config = config or ThreatIntelConfig()

        # Override from explicit parameters
        if nvd_api_key:
            self.config.nvd_api_key = nvd_api_key
        if github_token:
            self.config.github_token = github_token
        if db_path != "./data/threat_intel.db":
            self.config.storage_path = db_path

        # Initialize components
        self.db = ThreatIntelDatabase(self.config.storage_path)

        self._cve_sync: CVESyncService | None = None
        self._exploitdb: ExploitDBClient | None = None
        self._github: GitHubPoCSearcher | None = None
        self._scheduler: IntelSyncScheduler | None = None

        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the service (connect to database, etc.)."""
        if self._initialized:
            return

        await self.db.connect()
        self._initialized = True
        logger.info("Threat intelligence service initialized")

    async def close(self) -> None:
        """Close the service and release resources."""
        if self._scheduler:
            self._scheduler.stop()
        await self.db.close()
        self._initialized = False
        logger.info("Threat intelligence service closed")

    async def __aenter__(self) -> "IntelService":
        """Enter async context."""
        await self.initialize()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context."""
        await self.close()

    # ==================== CVE Operations ====================

    async def get_cve(self, cve_id: str) -> CVEInfo | None:
        """Get a CVE by ID.

        First checks database, then fetches from NVD if not found.

        Args:
            cve_id: CVE identifier.

        Returns:
            CVEInfo or None.
        """
        # Check database first
        cve = await self.db.get_cve(cve_id)
        if cve:
            return cve

        # Fetch from NVD
        if self._cve_sync is None:
            self._cve_sync = CVESyncService(nvd_api_key=self.config.nvd_api_key)

        async with self._cve_sync:
            cve = await self._cve_sync.get_cve(cve_id)
            if cve:
                await self.db.save_cve(cve)
            return cve

    async def search_cves(
        self,
        query: str,
        limit: int = 50,
        use_api: bool = False,
    ) -> list[CVEInfo]:
        """Search CVEs by keyword.

        Args:
            query: Search query.
            limit: Maximum results.
            use_api: Whether to search via API if not in database.

        Returns:
            List of CVEInfo objects.
        """
        # Search database first
        results = await self.db.search_cves(query, limit=limit)

        if len(results) >= limit or not use_api:
            return results

        # Search via API
        if self._cve_sync is None:
            self._cve_sync = CVESyncService(nvd_api_key=self.config.nvd_api_key)

        remaining = limit - len(results)
        found_ids = {c.cve_id for c in results}

        async with self._cve_sync:
            async for cve in self._cve_sync.search_cves(query):
                if cve.cve_id not in found_ids:
                    await self.db.save_cve(cve)
                    results.append(cve)
                    found_ids.add(cve.cve_id)
                    remaining -= 1
                    if remaining <= 0:
                        break

        return results

    async def get_recent_cves(self, days: int = 7, limit: int = 100) -> list[CVEInfo]:
        """Get recently published CVEs.

        Args:
            days: Days to look back.
            limit: Maximum results.

        Returns:
            List of CVEInfo objects.
        """
        return await self.db.get_recent_cves(days=days, limit=limit)

    async def get_kev_cves(self, limit: int = 100) -> list[CVEInfo]:
        """Get Known Exploited Vulnerabilities.

        Args:
            limit: Maximum results.

        Returns:
            List of CVEInfo objects.
        """
        return await self.db.get_kev_cves(limit=limit)

    # ==================== PoC Operations ====================

    async def get_pocs_for_cve(self, cve_id: str) -> list[PoCInfo]:
        """Get all PoCs for a CVE.

        Args:
            cve_id: CVE identifier.

        Returns:
            List of PoCInfo objects.
        """
        return await self.db.get_pocs_for_cve(cve_id)

    async def search_pocs_github(self, cve_id: str, limit: int = 30) -> list[PoCInfo]:
        """Search GitHub for PoCs.

        Args:
            cve_id: CVE identifier.
            limit: Maximum results.

        Returns:
            List of PoCInfo objects.
        """
        if self._github is None:
            self._github = GitHubPoCSearcher(
                token=self.config.github_token,
                min_stars=self.config.github_min_stars,
            )

        pocs = await self._github.search_cve(cve_id, limit=limit)

        # Save to database
        for poc in pocs:
            await self.db.save_poc(poc)

        return pocs

    async def sync_exploitdb(self) -> int:
        """Sync ExploitDB data.

        Returns:
            Number of exploits synced.
        """
        if self._exploitdb is None:
            self._exploitdb = ExploitDBClient()

        count = await self._exploitdb.sync()

        # Save all to database
        async for poc in self._exploitdb.iter_all():
            await self.db.save_poc(poc)

        return count

    # ==================== Sync Operations ====================

    async def sync_recent(self, days: int = 7) -> dict[str, Any]:
        """Sync recent CVEs.

        Args:
            days: Days to sync.

        Returns:
            Sync statistics.
        """
        if self._cve_sync is None:
            self._cve_sync = CVESyncService(nvd_api_key=self.config.nvd_api_key)

        stats = {
            "cves_synced": 0,
            "started_at": datetime.now(),
        }

        async with self._cve_sync:
            async for cve in self._cve_sync.sync_recent_cves(days=days):
                await self.db.save_cve(cve)
                stats["cves_synced"] += 1

        stats["completed_at"] = datetime.now()
        return stats

    async def sync_all(self) -> dict[str, Any]:
        """Perform full synchronization.

        Returns:
            Sync statistics.
        """
        stats = {
            "started_at": datetime.now(),
            "cves": 0,
            "exploits": 0,
            "errors": [],
        }

        try:
            # Sync CVEs
            cve_stats = await self.sync_recent(days=30)
            stats["cves"] = cve_stats["cves_synced"]
        except Exception as e:
            stats["errors"].append(f"CVE sync: {e}")

        try:
            # Sync ExploitDB
            stats["exploits"] = await self.sync_exploitdb()
        except Exception as e:
            stats["errors"].append(f"ExploitDB sync: {e}")

        stats["completed_at"] = datetime.now()
        return stats

    def start_scheduler(self) -> None:
        """Start the automatic sync scheduler."""
        if self._scheduler is None:
            self._scheduler = IntelSyncScheduler(
                db=self.db,
                nvd_api_key=self.config.nvd_api_key,
                github_token=self.config.github_token,
            )

        self._scheduler.start()
        logger.info("Threat intel scheduler started")

    def stop_scheduler(self) -> None:
        """Stop the automatic sync scheduler."""
        if self._scheduler:
            self._scheduler.stop()

    # ==================== Stats ====================

    async def get_stats(self) -> dict[str, Any]:
        """Get database statistics.

        Returns:
            Statistics dictionary.
        """
        return await self.db.get_stats()

    async def get_scheduler_jobs(self) -> list[dict[str, Any]]:
        """Get scheduled jobs.

        Returns:
            List of job info.
        """
        if self._scheduler:
            return self._scheduler.get_jobs()
        return []
