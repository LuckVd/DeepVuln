"""Scan repository for database operations."""

from datetime import datetime
from typing import Optional, Any

from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.web.models.scan import Scan, ScanPhase, ScanEvent, ScanStatus
from src.web.models.schemas import ScanCreate
from src.web.repositories.base import AsyncRepository


class ScanRepository(AsyncRepository[Scan, ScanCreate, dict]):
    """Repository for Scan model."""

    def __init__(self):
        """Initialize repository with Scan model."""
        super().__init__(Scan)

    async def get_with_phases(
        self,
        db: AsyncSession,
        *,
        id: int
    ) -> Optional[Scan]:
        """
        Get a scan with its phases.

        Args:
            db: Database session
            id: Scan ID

        Returns:
            Scan instance with phases loaded
        """
        result = await db.execute(
            select(Scan)
            .options(selectinload(Scan.phases))
            .where(Scan.id == id)
        )
        return result.scalar_one_or_none()

    async def get_with_events(
        self,
        db: AsyncSession,
        *,
        id: int,
        event_limit: int = 100
    ) -> Optional[dict]:
        """
        Get a scan with recent events.

        Args:
            db: Database session
            id: Scan ID
            event_limit: Maximum number of events to return

        Returns:
            Dictionary with scan and events
        """
        # Get scan
        scan_result = await db.execute(
            select(Scan).where(Scan.id == id)
        )
        scan = scan_result.scalar_one_or_none()

        if scan is None:
            return None

        # Get events
        events_result = await db.execute(
            select(ScanEvent)
            .where(ScanEvent.scan_id == id)
            .order_by(ScanEvent.created_at.desc())
            .limit(event_limit)
        )
        events = list(events_result.scalars().all())

        return {"scan": scan, "events": events}

    async def list_by_status(
        self,
        db: AsyncSession,
        *,
        status: list[str],
        skip: int = 0,
        limit: int = 100
    ) -> list[Scan]:
        """
        List scans by status.

        Args:
            db: Database session
            status: List of statuses to filter by
            skip: Number of records to skip
            limit: Maximum number of records to return

        Returns:
            List of scans
        """
        result = await db.execute(
            select(Scan)
            .where(Scan.status.in_(status))
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_running_scans(
        self,
        db: AsyncSession
    ) -> list[Scan]:
        """
        Get all currently running scans.

        Args:
            db: Database session

        Returns:
            List of running scans
        """
        result = await db.execute(
            select(Scan).where(Scan.status == ScanStatus.RUNNING)
        )
        return list(result.scalars().all())

    async def update_progress(
        self,
        db: AsyncSession,
        *,
        scan_id: int,
        progress_percent: int,
        current_phase: Optional[str] = None,
        current_step: Optional[str] = None,
        findings_count: Optional[int] = None,
        tokens_used: Optional[int] = None
    ) -> Optional[Scan]:
        """
        Update scan progress.

        Args:
            db: Database session
            scan_id: Scan ID
            progress_percent: Progress percentage
            current_phase: Current phase name
            current_step: Current step description
            findings_count: Number of findings found
            tokens_used: Total tokens used

        Returns:
            Updated scan instance or None
        """
        scan = await self.get(db, id=scan_id)
        if scan is None:
            return None

        scan.progress_percent = progress_percent
        if current_phase:
            scan.current_phase = current_phase
        if current_step:
            scan.current_step = current_step
        if findings_count is not None:
            scan.findings_count = findings_count
        if tokens_used is not None:
            scan.tokens_used = tokens_used

        db.add(scan)
        await db.flush()
        await db.refresh(scan)
        return scan

    async def update_status(
        self,
        db: AsyncSession,
        *,
        scan_id: int,
        status: str,
        error_message: Optional[str] = None
    ) -> Optional[Scan]:
        """
        Update scan status.

        Args:
            db: Database session
            scan_id: Scan ID
            status: New status
            error_message: Optional error message

        Returns:
            Updated scan instance or None
        """
        scan = await self.get(db, id=scan_id)
        if scan is None:
            return None

        scan.status = status

        if status == ScanStatus.RUNNING and scan.started_at is None:
            scan.started_at = datetime.utcnow()
        elif status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
            scan.completed_at = datetime.utcnow()

        if error_message:
            scan.error_message = error_message

        db.add(scan)
        await db.flush()
        await db.refresh(scan)
        return scan

    async def update_task_id(
        self,
        db: AsyncSession,
        *,
        scan_id: int,
        task_id: str
    ) -> Optional[Scan]:
        """
        Update Celery task ID for a scan.

        Args:
            db: Database session
            scan_id: Scan ID
            task_id: Celery task ID

        Returns:
            Updated scan instance or None
        """
        scan = await self.get(db, id=scan_id)
        if scan is None:
            return None

        scan.task_id = task_id
        db.add(scan)
        await db.flush()
        await db.refresh(scan)
        return scan
