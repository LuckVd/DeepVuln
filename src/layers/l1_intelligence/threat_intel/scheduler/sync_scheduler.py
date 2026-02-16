"""Synchronization scheduler for automated threat intel updates."""

from collections.abc import Callable
from datetime import datetime
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.threat_intel.collectors.cve_sync import CVESyncService
from src.layers.l1_intelligence.threat_intel.sources.pocs.exploitdb_client import (
    ExploitDBClient,
)
from src.layers.l1_intelligence.threat_intel.sources.pocs.github_search import (
    GitHubPoCSearcher,
)
from src.layers.l1_intelligence.threat_intel.storage.database import ThreatIntelDatabase

logger = get_logger(__name__)


class IntelSyncScheduler:
    """Scheduler for automated threat intelligence synchronization.

    Schedules periodic sync jobs for:
    - Recent CVEs (hourly)
    - Full sync (daily)
    - ExploitDB sync (weekly)
    """

    def __init__(
        self,
        db: ThreatIntelDatabase,
        nvd_api_key: str | None = None,
        github_token: str | None = None,
    ) -> None:
        """Initialize sync scheduler.

        Args:
            db: Database instance.
            nvd_api_key: NVD API key.
            github_token: GitHub token.
        """
        self.db = db
        self.nvd_api_key = nvd_api_key
        self.github_token = github_token

        self.scheduler = AsyncIOScheduler()
        self._running = False

        # Callbacks
        self._on_sync_complete: Callable[[str, dict], None] | None = None
        self._on_sync_error: Callable[[str, Exception], None] | None = None

    def on_sync_complete(self, callback: Callable[[str, dict], None]) -> None:
        """Set callback for sync completion.

        Args:
            callback: Callback function (source, stats).
        """
        self._on_sync_complete = callback

    def on_sync_error(self, callback: Callable[[str, Exception], None]) -> None:
        """Set callback for sync errors.

        Args:
            callback: Callback function (source, error).
        """
        self._on_sync_error = callback

    def start(self) -> None:
        """Start the scheduler with default jobs."""
        if self._running:
            logger.warning("Scheduler already running")
            return

        # Recent CVEs - hourly
        self.scheduler.add_job(
            self.sync_recent_cves,
            CronTrigger(hour="*"),
            id="sync_recent_cves",
            name="Sync Recent CVEs",
            replace_existing=True,
        )

        # Full CVE sync - daily at 2 AM
        self.scheduler.add_job(
            self.sync_full,
            CronTrigger(hour=2, minute=0),
            id="sync_full",
            name="Full CVE Sync",
            replace_existing=True,
        )

        # KEV sync - every 6 hours
        self.scheduler.add_job(
            self.sync_kev,
            CronTrigger(hour="*/6"),
            id="sync_kev",
            name="Sync CISA KEV",
            replace_existing=True,
        )

        # ExploitDB sync - weekly on Monday at 3 AM
        self.scheduler.add_job(
            self.sync_exploitdb,
            CronTrigger(day_of_week="mon", hour=3),
            id="sync_exploitdb",
            name="Sync ExploitDB",
            replace_existing=True,
        )

        self.scheduler.start()
        self._running = True
        logger.info("Threat intel sync scheduler started")

    def stop(self) -> None:
        """Stop the scheduler."""
        if self._running:
            self.scheduler.shutdown(wait=False)
            self._running = False
            logger.info("Threat intel sync scheduler stopped")

    async def sync_recent_cves(self) -> dict[str, Any]:
        """Sync CVEs from the last 24 hours.

        Returns:
            Sync statistics.
        """
        source = "nvd_recent"
        stats = {
            "source": source,
            "started_at": datetime.now(),
            "cves_synced": 0,
            "errors": [],
        }

        try:
            async with CVESyncService(nvd_api_key=self.nvd_api_key) as service:
                async for cve in service.sync_recent_cves(days=1):
                    await self.db.save_cve(cve)
                    stats["cves_synced"] += 1

            await self.db.update_sync_meta(source, stats["cves_synced"], "success")
            logger.info(f"Recent CVE sync complete: {stats['cves_synced']} CVEs")

        except Exception as e:
            stats["errors"].append(str(e))
            await self.db.update_sync_meta(source, 0, "failed")
            logger.error(f"Recent CVE sync failed: {e}")

            if self._on_sync_error:
                self._on_sync_error(source, e)

        stats["completed_at"] = datetime.now()

        if self._on_sync_complete:
            self._on_sync_complete(source, stats)

        return stats

    async def sync_full(self) -> dict[str, Any]:
        """Perform full CVE sync (last 30 days).

        Returns:
            Sync statistics.
        """
        source = "nvd_full"
        stats = {
            "source": source,
            "started_at": datetime.now(),
            "cves_synced": 0,
            "errors": [],
        }

        try:
            async with CVESyncService(nvd_api_key=self.nvd_api_key) as service:
                async for cve in service.sync_recent_cves(days=30):
                    await self.db.save_cve(cve)
                    stats["cves_synced"] += 1

                    # Progress logging
                    if stats["cves_synced"] % 100 == 0:
                        logger.info(f"Full sync progress: {stats['cves_synced']} CVEs")

            await self.db.update_sync_meta(source, stats["cves_synced"], "success")
            logger.info(f"Full CVE sync complete: {stats['cves_synced']} CVEs")

        except Exception as e:
            stats["errors"].append(str(e))
            await self.db.update_sync_meta(source, 0, "failed")
            logger.error(f"Full CVE sync failed: {e}")

            if self._on_sync_error:
                self._on_sync_error(source, e)

        stats["completed_at"] = datetime.now()

        if self._on_sync_complete:
            self._on_sync_complete(source, stats)

        return stats

    async def sync_kev(self) -> dict[str, Any]:
        """Sync CISA Known Exploited Vulnerabilities.

        Returns:
            Sync statistics.
        """
        source = "cisa_kev"
        stats = {
            "source": source,
            "started_at": datetime.now(),
            "kev_count": 0,
            "errors": [],
        }

        try:
            async with CVESyncService(nvd_api_key=self.nvd_api_key) as service:
                record = await service.sync_kev()
                stats["kev_count"] = record.records_fetched

                # Update CVE records with KEV status
                for cve_id in service.kev.get_all_kev_cves():
                    cve = await self.db.get_cve(cve_id)
                    if cve:
                        cve = service.kev.enrich_cve(cve)
                        await self.db.save_cve(cve)

            await self.db.update_sync_meta(source, stats["kev_count"], "success")
            logger.info(f"KEV sync complete: {stats['kev_count']} entries")

        except Exception as e:
            stats["errors"].append(str(e))
            await self.db.update_sync_meta(source, 0, "failed")
            logger.error(f"KEV sync failed: {e}")

            if self._on_sync_error:
                self._on_sync_error(source, e)

        stats["completed_at"] = datetime.now()

        if self._on_sync_complete:
            self._on_sync_complete(source, stats)

        return stats

    async def sync_exploitdb(self) -> dict[str, Any]:
        """Sync ExploitDB data.

        Returns:
            Sync statistics.
        """
        source = "exploitdb"
        stats = {
            "source": source,
            "started_at": datetime.now(),
            "exploits_synced": 0,
            "errors": [],
        }

        try:
            client = ExploitDBClient()
            await client.sync()

            # Save all exploits
            async for poc in client.iter_all():
                await self.db.save_poc(poc)
                stats["exploits_synced"] += 1

                if stats["exploits_synced"] % 1000 == 0:
                    logger.info(f"ExploitDB sync progress: {stats['exploits_synced']} exploits")

            await self.db.update_sync_meta(source, stats["exploits_synced"], "success")
            logger.info(f"ExploitDB sync complete: {stats['exploits_synced']} exploits")

        except Exception as e:
            stats["errors"].append(str(e))
            await self.db.update_sync_meta(source, 0, "failed")
            logger.error(f"ExploitDB sync failed: {e}")

            if self._on_sync_error:
                self._on_sync_error(source, e)

        stats["completed_at"] = datetime.now()

        if self._on_sync_complete:
            self._on_sync_complete(source, stats)

        return stats

    async def sync_pocs_for_cve(self, cve_id: str) -> list[str]:
        """Search and sync PoCs for a specific CVE.

        Args:
            cve_id: CVE identifier.

        Returns:
            List of PoC IDs found.
        """
        found_pocs = []

        # Search GitHub
        try:
            github = GitHubPoCSearcher(token=self.github_token)
            pocs = await github.search_cve(cve_id)

            for poc in pocs:
                await self.db.save_poc(poc)
                found_pocs.append(poc.poc_id)

        except Exception as e:
            logger.warning(f"GitHub search failed for {cve_id}: {e}")

        return found_pocs

    def add_custom_job(
        self,
        func: Callable,
        trigger: CronTrigger,
        job_id: str,
        **kwargs: Any,
    ) -> None:
        """Add a custom sync job.

        Args:
            func: Function to execute.
            trigger: Schedule trigger.
            job_id: Unique job ID.
            **kwargs: Additional arguments.
        """
        self.scheduler.add_job(
            func,
            trigger,
            id=job_id,
            replace_existing=True,
            **kwargs,
        )
        logger.info(f"Added custom job: {job_id}")

    def remove_job(self, job_id: str) -> bool:
        """Remove a scheduled job.

        Args:
            job_id: Job ID to remove.

        Returns:
            True if removed.
        """
        try:
            self.scheduler.remove_job(job_id)
            logger.info(f"Removed job: {job_id}")
            return True
        except Exception:
            return False

    def get_jobs(self) -> list[dict[str, Any]]:
        """Get list of scheduled jobs.

        Returns:
            List of job info dictionaries.
        """
        jobs = []
        for job in self.scheduler.get_jobs():
            jobs.append({
                "id": job.id,
                "name": job.name,
                "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
                "trigger": str(job.trigger),
            })
        return jobs

    @property
    def is_running(self) -> bool:
        """Check if scheduler is running."""
        return self._running
