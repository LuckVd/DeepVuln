"""Database event handler.

This module handles scan events by writing them to the database.
It bridges the in-memory event system with the persistent database layer.
"""

from datetime import datetime
from typing import Any
import asyncio
import logging


from ..events import ScanEvent, EventType
from ...models.database import get_session_local
from ...models.scan import Scan, ScanPhase
from ...models.finding import Finding


logger = logging.getLogger(__name__)


class DatabaseEventHandler:
    """Database event handler.

    This class handles scan events by writing them to the database.
    It's designed to be registered with the ScanEventEmitter.

    Example:
        handler = DatabaseEventHandler(AsyncSessionLocal)
        emitter.on(EventType.PHASE_START)(handler.on_phase_start)
    """

    def __init__(self, session_factory: Any):
        """Initialize database event handler.

        Args:
            session_factory: Database session factory
        """
        self.session_factory = session_factory

    async def on_scan_start(self, event: ScanEvent) -> None:
        """Handle scan start event.

        Args:
            event: Scan event
        """
        async with self.session_factory() as db:
            scan = await db.get(Scan, event.scan_id)
            if scan:
                scan.status = "running"
                scan.started_at = datetime.utcnow()
                await db.commit()

    async def on_scan_complete(self, event: ScanEvent) -> None:
        """Handle scan complete event.

        Args:
            event: Scan event
        """
        async with self.session_factory() as db:
            scan = await db.get(Scan, event.scan_id)
            if scan:
                scan.status = "completed"
                scan.completed_at = datetime.utcnow()
                scan.progress_percent = 100
                scan.findings_count = event.data.get("findings_total", 0)
                scan.tokens_used = event.data.get("tokens_used", 0)
                await db.commit()

    async def on_phase_start(self, event: ScanEvent) -> None:
        """Handle phase start event.

        Args:
            event: Scan event
        """
        async with self.session_factory() as db:
            phase = ScanPhase(
                scan_id=event.scan_id,
                phase_name=event.data.get("phase", ""),
                status="running",
                started_at=datetime.utcnow(),
            )
            db.add(phase)
            await db.commit()

    async def on_phase_complete(self, event: ScanEvent) -> None:
        """Handle phase complete event.

        Args:
            event: Scan event
        """
        from sqlalchemy import select, update

        phase_name = event.data.get("phase", "")

        async with self.session_factory() as db:
            # Find the running phase for this scan
            result = await db.execute(
                select(ScanPhase)
                .where(ScanPhase.scan_id == event.scan_id)
                .where(ScanPhase.phase_name == phase_name)
                .where(ScanPhase.status == "running")
            )

            phase = result.scalar_one_or_none()
            if phase:
                await db.execute(
                    update(ScanPhase)
                    .where(ScanPhase.id == phase.id)
                    .values(
                        status="completed",
                        completed_at=datetime.utcnow(),
                        duration_seconds=event.data.get("duration_seconds", 0),
                        findings_found=event.data.get("findings", 0),
                        tokens_used=event.data.get("tokens_used", 0),
                    )
                )
                await db.commit()

    async def on_engine_start(self, event: ScanEvent) -> None:
        """Handle engine start event.

        Args:
            event: Scan event
        """
        # Could track engine status in scan_phases table
        pass

    async def on_engine_complete(self, event: ScanEvent) -> None:
        """Handle engine complete event.

        Args:
            event: Scan event
        """
        # Could update engine-specific statistics
        pass

    async def on_finding_new(self, event: ScanEvent) -> None:
        """Handle new finding event.

        Args:
            event: Scan event
        """
        async with self.session_factory() as db:
            finding = Finding(
                scan_id=event.scan_id,
                vuln_type=event.data.get("vuln_type", ""),
                severity=event.data.get("severity", "medium"),
                confidence=event.data.get("confidence", 0.0),
                file_path=event.data.get("file_path", ""),
                line_start=event.data.get("line", 0),
                title=event.data.get("title", ""),
                engine=event.data.get("engine", ""),
                status="pending",
                code_snippet=event.data.get("code_snippet", ""),
            )
            db.add(finding)
            await db.commit()

    async def on_progress_update(self, event: ScanEvent) -> None:
        """Handle progress update event.

        Args:
            event: Scan event
        """
        async with self.session_factory() as db:
            scan = await db.get(Scan, event.scan_id)
            if scan:
                scan.progress_percent = event.data.get("progress_percent", 0)
                scan.current_phase = event.data.get("current_phase", "")
                scan.current_step = event.data.get("current_step", "")
                await db.commit()
