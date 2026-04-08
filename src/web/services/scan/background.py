"""Background scan service using FastAPI BackgroundTasks.

This module provides coroutine-based background task execution
as an alternative to Celery for scan processing.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import asyncio
import logging


logger = logging.getLogger(__name__)


async def execute_scan_task(
    scan_id: int,
    project_id: int,
    source_path: str | Path,
    config: dict[str, Any],
    db_session_factory: Any,
) -> dict[str, Any]:
    """Execute a scan task in the background.

    This is the entry point for background scan execution.
    It can be called from FastAPI BackgroundTasks or directly.

    Args:
        scan_id: Scan ID
        project_id: Project ID
        source_path: Path to source code
        config: Scan configuration
        db_session_factory: Database session factory

    Returns:
        Dictionary with scan results

    Example:
        from fastapi import BackgroundTasks

        @router.post("/scans/{scan_id}/start")
        async def start_scan(
            scan_id: int,
            background_tasks: BackgroundTasks,
            db: AsyncSession = Depends(get_db),
        ):
            # Get scan details...
            background_tasks.add_task(
                execute_scan_task,
                scan_id,
                project_id,
                source_path,
                config,
                AsyncSessionLocal,
            )
            return {"status": "started"}
    """
    from . import ScanOrchestrator, ScanConfig

    logger.info(f"Starting scan {scan_id} for project {project_id}")

    try:
        # Create orchestrator
        orchestrator = ScanOrchestrator(
            scan_id=scan_id,
            project_id=project_id,
            source_path=source_path,
            config=config,
            db_session_factory=db_session_factory,
        )

        # Run the scan
        result = await orchestrator.run()

        logger.info(
            f"Scan {scan_id} completed: "
            f"{result.get('statistics', {}).get('findings_count', 0)} findings"
        )

        return result

    except Exception as e:
        logger.exception(f"Scan {scan_id} failed")
        return {
            "success": False,
            "scan_id": scan_id,
            "error": str(e),
        }


class BackgroundScanManager:
    """Manager for background scan tasks.

    This class provides a simple way to manage multiple concurrent scans
    without the complexity of Celery.
    """

    def __init__(self, max_concurrent_scans: int = 3):
        """Initialize background scan manager.

        Args:
            max_concurrent_scans: Maximum number of concurrent scans
        """
        self.max_concurrent_scans = max_concurrent_scans
        self._running_scans: dict[int, asyncio.Task] = {}
        self._lock = asyncio.Lock()

    async def submit_scan(
        self,
        scan_id: int,
        project_id: int,
        source_path: str | Path,
        config: dict[str, Any],
        db_session_factory: Any,
    ) -> bool:
        """Submit a scan for background execution.

        Args:
            scan_id: Scan ID
            project_id: Project ID
            source_path: Path to source code
            config: Scan configuration
            db_session_factory: Database session factory

        Returns:
            True if scan was submitted, False if at capacity
        """
        async with self._lock:
            # Check capacity
            if len(self._running_scans) >= self.max_concurrent_scans:
                logger.warning(f"Scan capacity reached ({self.max_concurrent_scans})")
                return False

            # Check if scan already running
            if scan_id in self._running_scans:
                logger.warning(f"Scan {scan_id} already running")
                return False

            # Create task
            task = asyncio.create_task(
                execute_scan_task(
                    scan_id=scan_id,
                    project_id=project_id,
                    source_path=source_path,
                    config=config,
                    db_session_factory=db_session_factory,
                )
            )

            self._running_scans[scan_id] = task

            # Add callback to clean up
            task.add_done_callback(lambda t: self._cleanup_scan(scan_id))

            logger.info(f"Submitted scan {scan_id} (active: {len(self._running_scans)})")
            return True

    async def cancel_scan(self, scan_id: int) -> bool:
        """Cancel a running scan.

        Args:
            scan_id: Scan ID to cancel

        Returns:
            True if scan was cancelled
        """
        async with self._lock:
            task = self._running_scans.get(scan_id)
            if task and not task.done():
                task.cancel()
                logger.info(f"Cancelled scan {scan_id}")
                return True
            return False

    def _cleanup_scan(self, scan_id: int) -> None:
        """Clean up completed scan task.

        Args:
            scan_id: Scan ID to clean up
        """
        self._running_scans.pop(scan_id, None)
        logger.info(f"Cleaned up scan {scan_id} (active: {len(self._running_scans)})")

    async def get_status(self) -> dict[str, Any]:
        """Get manager status.

        Returns:
            Status dictionary with running scans
        """
        return {
            "max_concurrent_scans": self.max_concurrent_scans,
            "running_scans": len(self._running_scans),
            "scan_ids": list(self._running_scans.keys()),
        }


# Global singleton instance
_scan_manager: BackgroundScanManager | None = None


def get_scan_manager() -> BackgroundScanManager:
    """Get or create the global scan manager.

    Returns:
        BackgroundScanManager instance
    """
    global _scan_manager
    if _scan_manager is None:
        _scan_manager = BackgroundScanManager()
    return _scan_manager
