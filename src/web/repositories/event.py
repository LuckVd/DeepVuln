"""ScanPhase and ScanEvent repositories for database operations."""

from typing import Optional, Any

from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.web.models.scan import ScanPhase, ScanEvent
from src.web.models.schemas import FindingStatus
from src.web.repositories.base import AsyncRepository


class ScanPhaseRepository(AsyncRepository[ScanPhase, dict, dict]):
    """Repository for ScanPhase model."""

    def __init__(self):
        """Initialize repository with ScanPhase model."""
        super().__init__(ScanPhase)

    async def get_by_scan(
        self,
        db: AsyncSession,
        *,
        scan_id: int
    ) -> list[ScanPhase]:
        """
        Get all phases for a scan.

        Args:
            db: Database session
            scan_id: Scan ID

        Returns:
            List of scan phases
        """
        result = await db.execute(
            select(ScanPhase)
            .where(ScanPhase.scan_id == scan_id)
            .order_by(ScanPhase.id)
        )
        return list(result.scalars().all())

    async def get_by_name(
        self,
        db: AsyncSession,
        *,
        scan_id: int,
        phase_name: str
    ) -> Optional[ScanPhase]:
        """
        Get a specific phase for a scan.

        Args:
            db: Database session
            scan_id: Scan ID
            phase_name: Phase name

        Returns:
            ScanPhase instance or None
        """
        result = await db.execute(
            select(ScanPhase)
            .where(
                and_(
                    ScanPhase.scan_id == scan_id,
                    ScanPhase.phase_name == phase_name
                )
            )
        )
        return result.scalar_one_or_none()

    async def get_current_phase(
        self,
        db: AsyncSession,
        *,
        scan_id: int
    ) -> Optional[ScanPhase]:
        """
        Get the currently running phase for a scan.

        Args:
            db: Database session
            scan_id: Scan ID

        Returns:
            ScanPhase instance or None
        """
        result = await db.execute(
            select(ScanPhase)
            .where(
                and_(
                    ScanPhase.scan_id == scan_id,
                    ScanPhase.status == "running"
                )
            )
            .order_by(ScanPhase.id)
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def update_status(
        self,
        db: AsyncSession,
        *,
        phase_id: int,
        status: str,
        progress_percent: Optional[int] = None,
        findings_found: Optional[int] = None,
        tokens_used: Optional[int] = None
    ) -> Optional[ScanPhase]:
        """
        Update phase status.

        Args:
            db: Database session
            phase_id: Phase ID
            status: New status
            progress_percent: Progress percentage
            findings_found: Number of findings found
            tokens_used: Tokens used

        Returns:
            Updated phase or None
        """
        phase = await db.get(ScanPhase, phase_id)
        if phase is None:
            return None

        phase.status = status
        if progress_percent is not None:
            phase.progress_percent = progress_percent
        if findings_found is not None:
            phase.findings_found = findings_found
        if tokens_used is not None:
            phase.tokens_used = tokens_used

        await db.flush()
        await db.refresh(phase)
        return phase


class ScanEventRepository(AsyncRepository[ScanEvent, dict, dict]):
    """Repository for ScanEvent model."""

    def __init__(self):
        """Initialize repository with ScanEvent model."""
        super().__init__(ScanEvent)

    async def get_by_scan(
        self,
        db: AsyncSession,
        *,
        scan_id: int,
        skip: int = 0,
        limit: int = 100,
        event_type: Optional[str] = None
    ) -> list[ScanEvent]:
        """
        Get events for a scan.

        Args:
            db: Database session
            scan_id: Scan ID
            skip: Number of records to skip
            limit: Maximum number of records to return
            event_type: Optional event type filter

        Returns:
            List of scan events
        """
        query = select(ScanEvent).where(ScanEvent.scan_id == scan_id)

        if event_type:
            query = query.where(ScanEvent.event_type == event_type)

        query = query.order_by(ScanEvent.created_at).offset(skip).limit(limit)
        result = await db.execute(query)
        return list(result.scalars().all())

    async def get_recent_by_scan(
        self,
        db: AsyncSession,
        *,
        scan_id: int,
        limit: int = 50
    ) -> list[ScanEvent]:
        """
        Get recent events for a scan.

        Args:
            db: Database session
            scan_id: Scan ID
            limit: Maximum number of events to return

        Returns:
            List of recent scan events
        """
        result = await db.execute(
            select(ScanEvent)
            .where(ScanEvent.scan_id == scan_id)
            .order_by(desc(ScanEvent.created_at))
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_agent_conversation(
        self,
        db: AsyncSession,
        *,
        scan_id: int,
        limit: int = 100
    ) -> list[ScanEvent]:
        """
        Get agent conversation events for a scan.

        Args:
            db: Database session
            scan_id: Scan ID
            limit: Maximum number of events to return

        Returns:
            List of agent-related events
        """
        agent_event_types = [
            "agent_thinking",
            "agent_action",
            "adversarial_start",
            "adversarial_round",
            "adversarial_complete",
        ]

        result = await db.execute(
            select(ScanEvent)
            .where(
                and_(
                    ScanEvent.scan_id == scan_id,
                    ScanEvent.event_type.in_(agent_event_types)
                )
            )
            .order_by(ScanEvent.created_at.asc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def create_event(
        self,
        db: AsyncSession,
        *,
        scan_id: int,
        event_type: str,
        message: Optional[str] = None,
        details: Optional[dict] = None,
        engine_name: Optional[str] = None,
        file_path: Optional[str] = None,
        file_index: int = 0,
        file_total: int = 0,
        tokens_used: int = 0,
        agent_turn: int = 0,
        agent_role: Optional[str] = None,
        agent_message: Optional[str] = None
    ) -> ScanEvent:
        """
        Create a new scan event.

        Args:
            db: Database session
            scan_id: Scan ID
            event_type: Type of event
            message: Event message
            details: Additional details
            engine_name: Associated engine
            file_path: File being processed
            file_index: File index
            file_total: Total files
            tokens_used: Tokens consumed
            agent_turn: Agent turn number
            agent_role: Agent role
            agent_message: Agent message content

        Returns:
            Created event
        """
        from datetime import datetime

        event = ScanEvent(
            scan_id=scan_id,
            event_type=event_type,
            message=message,
            details=details,
            engine_name=engine_name,
            file_path=file_path,
            file_index=file_index,
            file_total=file_total,
            tokens_used=tokens_used,
            agent_turn=agent_turn,
            agent_role=agent_role,
            agent_message=agent_message,
            created_at=datetime.utcnow()
        )
        db.add(event)
        await db.flush()
        await db.refresh(event)
        return event
