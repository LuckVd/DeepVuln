"""Celery tasks for scan execution.

P10-07: This module defines Celery tasks for running security scans
in the background, allowing the API to return immediately while
the scan runs asynchronously.

UPDATED: Now uses ScanOrchestrator for direct engine invocation
instead of CLI subprocess approach (reference: DeepAudit design).
"""

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from celery import Task

from src.web.core.celery_app import get_celery_app
from src.web.models.database import get_session_local
from src.web.models.scan import Scan, ScanStatus
from src.web.repositories.scan import ScanRepository
from src.web.repositories.project import ProjectRepository
from src.web.services.scan_orchestrator import ScanOrchestrator
from src.web.services.progress_broadcaster import ProgressBroadcaster
from src.layers.l3_analysis.llm.client import LLMClient

logger = logging.getLogger(__name__)

# Get Celery app
celery_app = get_celery_app()


async def _execute_scan_async(
    scan_id: int,
    resume_from: Optional[str] = None,
) -> Dict[str, Any]:
    """Async implementation of scan execution.

    NEW: Uses ScanOrchestrator for direct engine invocation.

    Args:
        scan_id: ID of the scan to execute
        resume_from: Optional phase name to resume from (for future pause/resume)

    Returns:
        Dictionary with scan results
    """
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    # Create fresh database connection for this task
    from src.web.core.config import get_database_settings

    db_settings = get_database_settings()
    engine = create_async_engine(
        db_settings.url,
        echo=False,
        pool_pre_ping=True,
    )
    async_session_maker = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    scan_repo = ScanRepository()
    project_repo = ProjectRepository()

    try:
        # Get scan details from database
        async with async_session_maker() as db:
            scan = await scan_repo.get(db, id=scan_id)
            if scan is None:
                raise ValueError(f"Scan {scan_id} not found")

            # Verify project exists
            project = await project_repo.get(db, id=scan.project_id)
            if not project:
                raise ValueError(f"Project {scan.project_id} not found")

            # Update scan status to running
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(timezone.utc).replace(tzinfo=None)
            await scan_repo.update(db, db_obj=scan, obj_in={
                "status": ScanStatus.RUNNING,
                "started_at": scan.started_at,
            })

        # Create progress broadcaster
        progress_broadcaster = ProgressBroadcaster(
            scan_id=scan_id,
            db_session_factory=async_session_maker,
        )

        # Create LLM client for LLM-based features (P14-01)
        llm_client = None
        try:
            model = scan.config.get("model", "deepseek-chat")
            llm_client = LLMClient(model=model)
            logger.info(f"Scan {scan_id}: LLM client initialized with model: {model}")
        except Exception as e:
            logger.warning(f"Scan {scan_id}: Failed to initialize LLM client: {e}")

        # Create scan orchestrator (replaces CLIAdapter)
        orchestrator = ScanOrchestrator(
            scan_id=scan_id,
            project_id=scan.project_id,
            scan_config=scan.config,
            progress_callback=progress_broadcaster,
            db_session_factory=async_session_maker,
            llm_client=llm_client,
        )

        # Execute scan
        result = await orchestrator.execute_scan()

        # Update final scan status based on result
        async with async_session_maker() as db:
            if result["success"]:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
                scan.progress_percent = 100
                scan.findings_count = result.get("findings_count", 0)
            else:
                scan.status = ScanStatus.FAILED
                scan.error_message = result.get("error", "Unknown error")

            await scan_repo.update(db, db_obj=scan, obj_in={
                "status": scan.status,
                "completed_at": scan.completed_at,
                "progress_percent": scan.progress_percent,
                "findings_count": scan.findings_count,
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
            async with async_session_maker() as db:
                scan = await scan_repo.get(db, id=scan_id)
                if scan:
                    await scan_repo.update(db, db_obj=scan, obj_in={
                        "status": ScanStatus.FAILED,
                        "error_message": str(e),
                    })
        except Exception as db_error:
            logger.error(f"Failed to update scan status: {db_error}")

        return {
            "success": False,
            "scan_id": scan_id,
            "error": str(e),
            "findings_count": 0,
            "duration_seconds": 0,
        }

    finally:
        # Always close the engine
        await engine.dispose()


@celery_app.task(bind=True, name="execute_scan_task")
def execute_scan_task(
    self: Task,
    scan_id: int,
    resume_from: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute a security scan task.

    This Celery task runs the scan using direct engine invocation
    (via ScanOrchestrator) instead of subprocess CLI calls.

    Args:
        self: Celery task instance
        scan_id: ID of the scan to execute
        resume_from: Optional phase name to resume from (for future pause/resume)

    Returns:
        Dictionary containing:
            - success: bool - True if scan completed successfully
            - scan_id: int - The scan ID
            - error: str | None - Error message if failed
            - findings_count: int - Number of findings found
            - duration_seconds: float - Scan duration
    """
    # Run the async implementation in an event loop
    try:
        result = asyncio.run(_execute_scan_async(scan_id, resume_from))
        return result
    except Exception as e:
        logger.exception(f"Scan task failed for scan {scan_id}: {e}")
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
    from src.web.core.config import get_database_settings
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    # Create fresh database connection for this task
    db_settings = get_database_settings()
    engine = create_async_engine(
        db_settings.url,
        echo=False,
        pool_pre_ping=True,
    )
    async_session_maker = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    try:
        scan_repo = ScanRepository()

        async with async_session_maker() as db:
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
    finally:
        await engine.dispose()


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
