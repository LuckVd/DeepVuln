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
from typing import Any, Dict, Optional

from celery import Task

from src.web.core.celery_app import get_celery_app
from src.web.models.database import get_session_local
from src.web.models.scan import ScanStatus
from src.web.repositories.scan import ScanRepository
from src.web.services.scan_orchestrator import ScanOrchestrator
from src.web.services.progress_broadcaster import ProgressBroadcaster

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

    try:
        # Get scan details from database
        async with async_session_maker() as db:
            scan = await scan_repo.get(db, id=scan_id)
            if scan is None:
                raise ValueError(f"Scan {scan_id} not found")

            # Idempotency guard: skip if already completed/cancelled
            if scan.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
                logger.warning(f"Scan {scan_id} already {scan.status}, skipping execution")
                return

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
            # Get LLM config from database (agent_scan type)
            from src.web.services.llm_config_service import LLMConfigService

            async with async_session_maker() as db:
                llm_config = await LLMConfigService.get_agent_scan_config(db)
                if llm_config:
                    llm_client = LLMConfigService.create_llm_client(llm_config)
                    logger.info(
                        f"Scan {scan_id}: LLM client initialized from database with "
                        f"config: {llm_config.name} ({llm_config.provider}/{llm_config.model})"
                    )
                else:
                    logger.warning(f"Scan {scan_id}: No agent_scan LLM config found in database")
        except Exception as e:
            logger.warning(f"Scan {scan_id}: Failed to initialize LLM client from database: {e}")

        # Create scan orchestrator (replaces CLIAdapter)
        orchestrator = ScanOrchestrator(
            scan_id=scan_id,
            source_path=scan.source_path,
            scan_config=scan.config,
            progress_callback=progress_broadcaster,
            db_session_factory=async_session_maker,
            llm_client=llm_client,
            source_type=scan.source_type,
        )

        # Execute scan (pass resume_from so checkpoint-based resume is honored)
        result = await orchestrator.execute_scan(resume_from=resume_from)

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


def _emergency_mark_scan_failed(scan_id: int, error_message: str) -> None:
    """Synchronously mark a scan as failed using a fresh DB connection.

    This is a last-resort fallback when the async event loop is dead
    (e.g. SoftTimeLimitExceeded) and the normal async DB update cannot run.
    """
    from sqlalchemy import create_engine, text
    from src.web.core.config import get_database_settings

    try:
        settings = get_database_settings()
        # Convert async URL to sync (asyncpg -> psycopg2 or similar)
        sync_url = settings.url.replace("+asyncpg", "+psycopg2").replace("+aiosqlite", "")
        sync_engine = create_engine(sync_url, isolation_level="AUTOCOMMIT")
        with sync_engine.connect() as conn:
            conn.execute(
                text(
                    "UPDATE scans SET status = 'failed', "
                    "error_message = :err, "
                    "completed_at = NOW() "
                    "WHERE id = :sid AND status IN ('running', 'pending')"
                ),
                {"err": error_message[:500], "sid": scan_id},
            )
        sync_engine.dispose()
        logger.info(f"Emergency DB update: scan {scan_id} marked as failed")
    except Exception as e:
        logger.error(f"Emergency DB update also failed for scan {scan_id}: {e}")


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
        # Async event loop may be dead (SoftTimeLimitExceeded etc.),
        # use synchronous DB update as fallback to fix zombie status
        _emergency_mark_scan_failed(scan_id, str(e))
        return {
            "success": False,
            "scan_id": scan_id,
            "error": str(e),
            "findings_count": 0,
            "duration_seconds": 0,
        }

