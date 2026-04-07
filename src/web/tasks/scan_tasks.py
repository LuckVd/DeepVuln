"""Celery tasks for scan execution.

P10-07: This module defines Celery tasks for running security scans
in the background, allowing the API to return immediately while
the scan runs asynchronously.
"""

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from celery import Task

from src.web.core.celery_app import get_celery_app
from src.web.models.database import AsyncSessionLocal
from src.web.models.scan import Scan, ScanStatus
from src.web.repositories.scan import ScanRepository
from src.web.repositories.event import ScanEventRepository, ScanPhaseRepository

logger = logging.getLogger(__name__)

# Get Celery app
celery_app = get_celery_app()


async def _execute_scan_async(scan_id: int) -> Dict[str, Any]:
    """Async implementation of scan execution.

    Args:
        scan_id: ID of the scan to execute

    Returns:
        Dictionary with scan results
    """
    from src.web.services.cli_adapter import CLIAdapter

    scan_repo = ScanRepository()
    phase_repo = ScanPhaseRepository()
    event_repo = ScanEventRepository()

    try:
        # Get scan details from database
        async with AsyncSessionLocal() as db:
            scan = await scan_repo.get(db, id=scan_id)
            if scan is None:
                raise ValueError(f"Scan {scan_id} not found")

            # Update scan status to running
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(timezone.utc)
            await scan_repo.update(db, db_obj=scan, obj_in={
                "status": ScanStatus.RUNNING,
                "started_at": scan.started_at,
            })

            # Get project details
            project_id = scan.project_id

        # Create CLI adapter
        cli_adapter = CLIAdapter(
            scan_id=scan_id,
            project_id=project_id,
            scan_config=scan.config,
        )

        # Execute CLI scan (this is already async)
        result = await cli_adapter.run_scan()

        # Update scan status based on result
        async with AsyncSessionLocal() as db:
            if result["success"]:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.now(timezone.utc)
                scan.progress_percent = 100
                scan.findings_count = result.get("findings_count", 0)
                scan.tokens_used = result.get("tokens_used", 0)
            else:
                scan.status = ScanStatus.FAILED
                scan.error_message = result.get("error", "Unknown error")

            await scan_repo.update(db, db_obj=scan, obj_in={
                "status": scan.status,
                "completed_at": scan.completed_at,
                "progress_percent": scan.progress_percent,
                "findings_count": scan.findings_count,
                "tokens_used": scan.tokens_used,
                "error_message": scan.error_message,
            })

        return {
            "success": result["success"],
            "scan_id": scan_id,
            "error": result.get("error"),
            "findings_count": result.get("findings_count", 0),
            "duration_seconds": result.get("duration_seconds", 0),
        }

    except Exception as e:
        logger.exception(f"Scan task failed for scan {scan_id}: {e}")

        # Update scan status to failed
        try:
            async with AsyncSessionLocal() as db:
                scan = await scan_repo.get(db, id=scan_id)
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = str(e)
                    await scan_repo.update(db, db_obj=scan)
        except Exception as db_error:
            logger.error(f"Failed to update scan status: {db_error}")

        return {
            "success": False,
            "scan_id": scan_id,
            "error": str(e),
            "findings_count": 0,
            "duration_seconds": 0,
        }


@celery_app.task(bind=True, name="execute_scan_task")
def execute_scan_task(self: Task, scan_id: int) -> Dict[str, Any]:
    """Execute a security scan task.

    This Celery task runs the deepvuln CLI as a subprocess and updates
    the scan status in the database. It also parses the JSONL output
    to emit real-time progress events.

    Args:
        self: Celery task instance
        scan_id: ID of the scan to execute

    Returns:
        Dictionary containing:
            - success: bool - True if scan completed successfully
            - scan_id: int - The scan ID
            - error: str | None - Error message if failed
            - findings_count: int - Number of findings found
            - duration_seconds: float - Scan duration
    """
    # Update task state
    self.update_state(state="PROGRESS", meta={"scan_id": scan_id})

    # Run the async implementation in an event loop
    try:
        result = asyncio.run(_execute_scan_async(scan_id))
        return result
    except Exception as e:
        logger.exception(f"Scan task failed for scan {scan_id}: {e}")
        self.update_state(
            state="FAILURE",
            meta={"scan_id": scan_id, "error": str(e)}
        )
        return {
            "success": False,
            "scan_id": scan_id,
            "error": str(e),
            "findings_count": 0,
            "duration_seconds": 0,
        }


async def _check_scan_progress_async(scan_id: int) -> Dict[str, Any]:
    """Async implementation of scan progress check.

    Args:
        scan_id: ID of the scan to check

    Returns:
        Dictionary containing current scan status
    """
    scan_repo = ScanRepository()

    async with AsyncSessionLocal() as db:
        scan = await scan_repo.get(db, id=scan_id)
        if scan is None:
            return {
                "success": False,
                "error": f"Scan {scan_id} not found",
            }

        return {
            "success": True,
            "scan_id": scan_id,
            "status": scan.status,
            "progress_percent": scan.progress_percent,
            "current_phase": scan.current_phase,
            "findings_count": scan.findings_count,
            "tokens_used": scan.tokens_used,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "error_message": scan.error_message,
        }


@celery_app.task(name="check_scan_progress")
def check_scan_progress_task(scan_id: int) -> Dict[str, Any]:
    """Check the progress of a running scan.

    This task can be used to poll for scan status from the frontend.

    Args:
        scan_id: ID of the scan to check

    Returns:
        Dictionary containing current scan status
    """
    try:
        result = asyncio.run(_check_scan_progress_async(scan_id))
        return result
    except Exception as e:
        logger.exception(f"Progress check failed for scan {scan_id}: {e}")
        return {
            "success": False,
            "error": str(e),
        }
