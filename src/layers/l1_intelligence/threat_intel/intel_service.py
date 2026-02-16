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

    async def get_recent_kevs(self, days: int = 30, limit: int = 50) -> list[CVEInfo]:
        """Get recently added KEV entries.

        Args:
            days: Days to look back.
            limit: Maximum results.

        Returns:
            List of CVEInfo objects marked as KEV.
        """
        # Get KEV CVEs and filter by recent date
        all_kevs = await self.db.get_kev_cves(limit=limit * 2)
        cutoff = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        from datetime import timedelta

        cutoff = cutoff - timedelta(days=days)

        recent = [cve for cve in all_kevs if cve.published_date and cve.published_date >= cutoff]
        return recent[:limit]

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

    async def sync_cves(self, days: int = 7) -> dict[str, Any]:
        """Sync recent CVEs from NVD.

        Args:
            days: Days to sync.

        Returns:
            Sync statistics.
        """
        await self.initialize()

        if self._cve_sync is None:
            self._cve_sync = CVESyncService(nvd_api_key=self.config.nvd_api_key)

        stats = {
            "cves_synced": 0,
            "days": days,
            "started_at": datetime.now(),
            "nvd_success": True,
        }

        try:
            async with self._cve_sync:
                async for cve in self._cve_sync.sync_recent_cves(days=days):
                    await self.db.save_cve(cve)
                    stats["cves_synced"] += 1
        except Exception as e:
            stats["nvd_success"] = False
            stats["error"] = str(e)
            logger.error(f"CVE sync failed: {e}")

        stats["completed_at"] = datetime.now()
        return stats

    async def sync_kev(self) -> int:
        """Sync Known Exploited Vulnerabilities from CISA.

        Returns:
            Number of KEV entries synced.
        """
        await self.initialize()

        from src.layers.l1_intelligence.threat_intel.sources.vulnerabilities.cisa_kev import (
            CISAKEVClient,
        )

        kev_client = CISAKEVClient()
        count = await kev_client.sync()

        # Mark CVEs in database as KEV
        kev_cves = kev_client.get_all_kev_cves()
        for cve_id in kev_cves:
            cve = await self.db.get_cve(cve_id)
            if cve and not cve.kev:
                cve.kev = True
                if "known-exploited" not in cve.tags:
                    cve.tags.append("known-exploited")
                await self.db.save_cve(cve)

        logger.info(f"Synced {count} KEV entries")
        return count

    async def sync_recent(self, days: int = 7) -> dict[str, Any]:
        """Sync recent CVEs. (Alias for sync_cves)

        Args:
            days: Days to sync.

        Returns:
            Sync statistics.
        """
        return await self.sync_cves(days=days)

    async def sync_all(self, days: int = 30) -> dict[str, Any]:
        """Perform full synchronization.

        Args:
            days: Days to sync for CVEs.

        Returns:
            Sync statistics.
        """
        await self.initialize()

        stats = {
            "started_at": datetime.now(),
            "cves_synced": 0,
            "kev_synced": 0,
            "exploits_synced": 0,
            "errors": [],
        }

        try:
            # Sync CVEs
            cve_stats = await self.sync_cves(days=days)
            stats["cves_synced"] = cve_stats.get("cves_synced", 0)
        except Exception as e:
            stats["errors"].append(f"CVE sync: {e}")

        try:
            # Sync KEV
            stats["kev_synced"] = await self.sync_kev()
        except Exception as e:
            stats["errors"].append(f"KEV sync: {e}")

        try:
            # Sync ExploitDB
            stats["exploits_synced"] = await self.sync_exploitdb()
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

    async def check_database_status(self) -> dict[str, Any]:
        """Check database status and return recommendations.

        Returns:
            Dictionary with status information:
            - exists: bool - whether database file exists
            - is_empty: bool - whether database has no CVEs
            - is_stale: bool - whether database hasn't been synced recently
            - last_sync: datetime | None - last sync time
            - total_cves: int - number of CVEs in database
            - kev_count: int - number of KEV entries
            - recommendation: str - recommended action
            - days_since_sync: int | None - days since last sync
        """
        from datetime import timedelta
        from pathlib import Path

        result = {
            "exists": False,
            "is_empty": True,
            "is_stale": False,
            "last_sync": None,
            "total_cves": 0,
            "kev_count": 0,
            "recommendation": "sync",
            "days_since_sync": None,
        }

        # Check if database file exists
        db_path = Path(self.config.storage_path)
        result["exists"] = db_path.exists()

        if not result["exists"]:
            result["recommendation"] = "first_sync"
            return result

        # Connect and check contents
        was_initialized = self._initialized
        if not was_initialized:
            await self.initialize()

        try:
            stats = await self.db.get_stats()
            result["total_cves"] = stats.get("total_cves", 0)
            result["kev_count"] = stats.get("kev_count", 0)
            result["is_empty"] = result["total_cves"] == 0

            # Check last sync time
            nvd_meta = await self.db.get_sync_meta("nvd")
            if nvd_meta and nvd_meta.get("last_success"):
                try:
                    last_sync = datetime.fromisoformat(nvd_meta["last_success"])
                    result["last_sync"] = last_sync
                    days_since = (datetime.now() - last_sync).days
                    result["days_since_sync"] = days_since

                    # Consider stale if > 7 days
                    if days_since > 7:
                        result["is_stale"] = True
                        result["recommendation"] = "update"
                except Exception:
                    pass

            # Determine recommendation
            if result["is_empty"]:
                result["recommendation"] = "first_sync"
            elif result["is_stale"]:
                result["recommendation"] = "update"
            else:
                result["recommendation"] = "ok"

        finally:
            if not was_initialized:
                await self.close()

        return result

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
