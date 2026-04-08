"""Progress broadcaster for scan progress updates.

This module provides the ProgressBroadcaster class that implements the
ProgressCallback protocol and updates both the database and WebSocket
connections with scan progress events.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from src.web.api.websocket import (
    ConnectionManager,
    get_connection_manager,
    ScanEventBroadcaster,
)
from src.web.models.database import get_session_local
from src.web.models.scan import Scan, ScanPhase, ScanEvent, ScanStatus
from src.web.repositories.scan import ScanRepository
from src.web.repositories.event import ScanPhaseRepository, ScanEventRepository
from src.web.models.finding import Finding

logger = logging.getLogger(__name__)


def _utc_now_naive() -> datetime:
    """Get current UTC time as naive datetime (for database compatibility)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ============================================================================
# Progress Callback Protocol
# ============================================================================


class ProgressCallback(Protocol):
    """Protocol for scan progress callbacks.

    Any class that implements these methods can be used as a progress
    callback for ScanOrchestrator.
    """

    async def on_phase_start(self, phase_name: str, **data: Any) -> None:
        """Called when a scan phase starts."""
        ...

    async def on_phase_complete(
        self, phase_name: str, result: Dict[str, Any]
    ) -> None:
        """Called when a scan phase completes."""
        ...

    async def on_engine_start(self, engine_name: str) -> None:
        """Called when an analysis engine starts."""
        ...

    async def on_engine_complete(
        self, engine_name: str, findings_count: int, duration_seconds: float = 0
    ) -> None:
        """Called when an analysis engine completes."""
        ...

    async def on_engine_failed(self, engine_name: str, error: str) -> None:
        """Called when an analysis engine fails."""
        ...

    async def on_finding(self, finding: Any) -> None:
        """Called when a new finding is discovered."""
        ...

    async def on_progress(
        self, progress_percent: int, message: Optional[str] = None
    ) -> None:
        """Called with progress updates."""
        ...

    async def on_scan_complete(
        self, findings_count: int, duration_seconds: float
    ) -> None:
        """Called when the scan completes."""
        ...

    async def on_scan_failed(self, error: str) -> None:
        """Called when the scan fails."""
        ...

    async def on_warning(self, message: str) -> None:
        """Called when a non-fatal issue occurs."""
        ...


# ============================================================================
# Progress Broadcaster
# ============================================================================


class ProgressBroadcaster:
    """Broadcasts scan progress to database and WebSocket clients.

    This class implements the ProgressCallback protocol and provides
    unified progress tracking for scan operations.

    It updates:
    1. Database records (Scan, ScanPhase, ScanEvent)
    2. WebSocket connections (real-time push)
    """

    def __init__(
        self,
        scan_id: int,
        db_session_factory: Optional[Callable[[], AsyncSession]] = None,
        websocket_manager: Optional[ConnectionManager] = None,
    ):
        """Initialize the progress broadcaster.

        Args:
            scan_id: ID of the scan being tracked
            db_session_factory: Factory function for creating DB sessions
            websocket_manager: Optional WebSocket manager (uses global if None)
        """
        self.scan_id = scan_id
        self.db_session_factory = db_session_factory or get_session_local
        self.websocket_manager = websocket_manager or get_connection_manager()

        # Create event broadcaster for WebSocket
        self.event_broadcaster = ScanEventBroadcaster(self.websocket_manager)

        # Repositories
        self.scan_repo = ScanRepository()
        self.phase_repo = ScanPhaseRepository()
        self.event_repo = ScanEventRepository()

        # Phase weight tracking for progress calculation
        self.phase_weights = {
            "source_preparation": 5,
            "tech_stack_detection": 5,
            "engine_selection": 5,
            "engine_execution": 80,
            "result_merging": 5,
        }
        self.current_phase: Optional[str] = None
        self.phase_start_time: Optional[datetime] = None

        # Track completed phases for cumulative progress
        self._completed_phases: set = set()

    def _get_db_session(self) -> AsyncSession:
        """Get a new database session."""
        return self.db_session_factory()

    async def on_phase_start(self, phase_name: str, **data: Any) -> None:
        """Handle phase start event.

        Creates a ScanPhase record and broadcasts to WebSocket.
        """
        self.current_phase = phase_name
        self.phase_start_time = _utc_now_naive()

        async with self._get_db_session() as db:
            # Create phase record
            phase = ScanPhase(
                scan_id=self.scan_id,
                phase_name=phase_name,
                status="running",
                started_at=self.phase_start_time,
            )
            await self.phase_repo.create(db, obj_in=phase)
            await db.commit()

        # Broadcast to WebSocket
        await self.event_broadcaster.broadcast_phase_start(
            self.scan_id, phase_name, phase_data=data
        )

        # Update scan current phase
        await self._update_scan({"current_phase": phase_name})

        logger.debug(f"Phase '{phase_name}' started for scan {self.scan_id}")

    async def on_phase_complete(
        self, phase_name: str, result: Dict[str, Any]
    ) -> None:
        """Handle phase complete event.

        Updates ScanPhase record and broadcasts to WebSocket.
        """
        if self.phase_start_time:
            duration_seconds = (
                _utc_now_naive() - self.phase_start_time
            ).total_seconds()
        else:
            duration_seconds = 0

        self._completed_phases.add(phase_name)

        async with self._get_db_session() as db:
            # Find and update the phase record
            from sqlalchemy import select, update

            phase_query = (
                select(ScanPhase)
                .where(ScanPhase.scan_id == self.scan_id)
                .where(ScanPhase.phase_name == phase_name)
                .where(ScanPhase.status == "running")
            )

            phase_result = await db.execute(phase_query)
            phase = phase_result.scalar_one_or_none()

            if phase:
                await db.execute(
                    update(ScanPhase)
                    .where(ScanPhase.id == phase.id)
                    .values(
                        status="completed",
                        completed_at=_utc_now_naive(),
                        duration_seconds=int(duration_seconds),
                        findings_found=result.get("findings", 0),
                        tokens_used=result.get("tokens_used", 0),
                    )
                )
                await db.commit()

        # Broadcast to WebSocket
        await self.event_broadcaster.broadcast_phase_complete(
            self.scan_id,
            phase_name,
            duration_seconds,
            findings=result.get("findings", 0),
            tokens_used=result.get("tokens_used", 0),
        )

        logger.debug(
            f"Phase '{phase_name}' completed for scan {self.scan_id} "
            f"in {duration_seconds:.2f}s"
        )

    async def on_engine_start(self, engine_name: str) -> None:
        """Handle engine start event."""
        # Create event in database
        await self._create_event(
            event_type="engine_start",
            message=f"Engine '{engine_name}' started",
            engine_name=engine_name,
        )

        # Broadcast to WebSocket
        await self.event_broadcaster.broadcast_scan_progress(
            self.scan_id,
            progress_percent=self._calculate_progress(),
            message=f"Running {engine_name} analysis...",
        )

        logger.debug(f"Engine '{engine_name}' started for scan {self.scan_id}")

    async def on_engine_complete(
        self, engine_name: str, findings_count: int, duration_seconds: float = 0
    ) -> None:
        """Handle engine complete event."""
        # Create event in database
        await self._create_event(
            event_type="engine_complete",
            message=f"Engine '{engine_name}' completed with {findings_count} findings",
            engine_name=engine_name,
            details={
                "findings_count": findings_count,
                "duration_seconds": duration_seconds,
            },
        )

        # Broadcast to WebSocket
        await self.event_broadcaster.broadcast_scan_progress(
            self.scan_id,
            progress_percent=self._calculate_progress(),
            message=f"{engine_name} analysis complete: {findings_count} findings",
        )

        logger.debug(
            f"Engine '{engine_name}' completed for scan {self.scan_id}: "
            f"{findings_count} findings"
        )

    async def on_engine_failed(self, engine_name: str, error: str) -> None:
        """Handle engine failure event."""
        # Create event in database
        await self._create_event(
            event_type="engine_failed",
            message=f"Engine '{engine_name}' failed: {error}",
            engine_name=engine_name,
            event_level="warning",
        )

        # Broadcast to WebSocket
        await self.event_broadcaster.broadcast_scan_progress(
            self.scan_id,
            progress_percent=self._calculate_progress(),
            message=f"{engine_name} analysis failed: {error}",
        )

        logger.warning(
            f"Engine '{engine_name}' failed for scan {self.scan_id}: {error}"
        )

    async def on_finding(self, finding: Any) -> None:
        """Handle new finding event.

        Extracts finding data and broadcasts to WebSocket.
        """
        # Convert finding to dict
        if isinstance(finding, Finding):
            finding_data = {
                "id": finding.id,
                "vuln_type": finding.vuln_type,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "file_path": finding.file_path,
                "line_start": finding.line_start,
                "title": finding.title,
                "engine": finding.engine,
            }
        elif hasattr(finding, "model_dump"):
            finding_data = finding.model_dump()
        elif isinstance(finding, dict):
            finding_data = finding
        else:
            # Fallback for other types
            finding_data = {
                "title": getattr(finding, "title", "Unknown"),
                "severity": getattr(finding, "severity", "unknown"),
                "file_path": getattr(finding, "file_path", "unknown"),
            }

        # Broadcast to WebSocket
        await self.event_broadcaster.broadcast_finding(
            self.scan_id, finding_data
        )

    async def on_progress(
        self, progress_percent: int, message: Optional[str] = None
    ) -> None:
        """Handle progress update event."""
        # Update scan record
        await self._update_scan({"progress_percent": progress_percent})

        # Broadcast to WebSocket
        await self.event_broadcaster.broadcast_scan_progress(
            self.scan_id,
            progress_percent=progress_percent,
            message=message,
        )

    async def on_scan_complete(
        self, findings_count: int, duration_seconds: float
    ) -> None:
        """Handle scan complete event."""
        # Update scan record
        await self._update_scan(
            {
                "status": ScanStatus.COMPLETED,
                "progress_percent": 100,
                "findings_count": findings_count,
                "completed_at": _utc_now_naive(),
            }
        )

        # Get total tokens used from events
        tokens_used = await self._get_total_tokens_used()

        # Broadcast to WebSocket
        await self.event_broadcaster.broadcast_scan_complete(
            self.scan_id, findings_count, duration_seconds, tokens_used
        )

        # Create completion event
        await self._create_event(
            event_type="scan_complete",
            message=f"Scan completed with {findings_count} findings",
            details={
                "findings_count": findings_count,
                "duration_seconds": duration_seconds,
                "tokens_used": tokens_used,
            },
        )

        logger.info(
            f"Scan {self.scan_id} completed: {findings_count} findings, "
            f"{duration_seconds:.2f}s, {tokens_used} tokens"
        )

    async def on_scan_failed(self, error: str) -> None:
        """Handle scan failure event."""
        # Update scan record
        await self._update_scan(
            {
                "status": ScanStatus.FAILED,
                "error_message": error,
            }
        )

        # Broadcast to WebSocket
        await self.event_broadcaster.broadcast_scan_failed(self.scan_id, error)

        # Create failure event
        await self._create_event(
            event_type="scan_failed",
            message=f"Scan failed: {error}",
            event_level="error",
        )

        logger.error(f"Scan {self.scan_id} failed: {error}")

    async def on_warning(self, message: str) -> None:
        """Handle warning event."""
        # Create warning event
        await self._create_event(
            event_type="warning",
            message=message,
            event_level="warning",
        )

        logger.warning(f"Scan {self.scan_id} warning: {message}")

    # ========================================================================
    # Private Helper Methods
    # ========================================================================

    async def _update_scan(self, update_data: Dict[str, Any]) -> None:
        """Update scan record in database.

        Args:
            update_data: Dictionary of fields to update
        """
        async with self._get_db_session() as db:
            # Get the scan object first
            scan = await self.scan_repo.get(db, id=self.scan_id)
            if scan:
                await self.scan_repo.update(
                    db, db_obj=scan, obj_in=update_data
                )
                await db.commit()

    async def _create_event(
        self,
        event_type: str,
        message: Optional[str] = None,
        engine_name: Optional[str] = None,
        event_level: str = "info",
        details: Optional[Dict[str, Any]] = None,
    ) -> ScanEvent:
        """Create a scan event record.

        Args:
            event_type: Type of event
            message: Event message
            engine_name: Associated engine name
            event_level: Event level (info, warning, error)
            details: Additional event details

        Returns:
            Created ScanEvent instance
        """
        async with self._get_db_session() as db:
            event = ScanEvent(
                scan_id=self.scan_id,
                event_type=event_type,
                event_level=event_level,
                message=message,
                engine_name=engine_name,
                details=details,
            )
            created_event = await self.event_repo.create(db, obj_in=event)
            await db.commit()
            await db.refresh(created_event)
            return created_event

    def _calculate_progress(self) -> int:
        """Calculate overall progress based on completed phases.

        Returns:
            Progress percentage (0-100)
        """
        # Phase order for progress calculation
        phase_order = [
            "source_preparation",
            "tech_stack_detection",
            "engine_selection",
            "engine_execution",
            "result_merging",
        ]

        total_weight = sum(self.phase_weights.values())
        completed_weight = 0

        for phase in phase_order:
            if phase in self._completed_phases:
                completed_weight += self.phase_weights.get(phase, 0)
            elif phase == self.current_phase:
                # Current phase gets partial progress
                # For simplicity, assume 50% of current phase completed
                completed_weight += self.phase_weights.get(phase, 0) * 0.5
                break

        return int((completed_weight / total_weight) * 100) if total_weight > 0 else 0

    async def _get_total_tokens_used(self) -> int:
        """Get total tokens used from all phases.

        Returns:
            Total tokens used
        """
        async with self._get_db_session() as db:
            from sqlalchemy import select, func

            result = await db.execute(
                select(func.sum(ScanPhase.tokens_used)).where(
                    ScanPhase.scan_id == self.scan_id
                )
            )
            return result.scalar_one() or 0


# ============================================================================
# Default Progress Callback
# ============================================================================


class DefaultProgressCallback:
    """Simple default progress callback that logs events.

    Used when no real-time progress tracking is needed.
    """

    def __init__(self, scan_id: int):
        self.scan_id = scan_id

    async def on_phase_start(self, phase_name: str, **data: Any) -> None:
        logger.info(f"Scan {self.scan_id}: Phase '{phase_name}' started")

    async def on_phase_complete(
        self, phase_name: str, result: Dict[str, Any]
    ) -> None:
        logger.info(
            f"Scan {self.scan_id}: Phase '{phase_name}' completed - {result}"
        )

    async def on_engine_start(self, engine_name: str) -> None:
        logger.info(f"Scan {self.scan_id}: Engine '{engine_name}' started")

    async def on_engine_complete(
        self, engine_name: str, findings_count: int, duration_seconds: float = 0
    ) -> None:
        logger.info(
            f"Scan {self.scan_id}: Engine '{engine_name}' completed - "
            f"{findings_count} findings"
        )

    async def on_engine_failed(self, engine_name: str, error: str) -> None:
        logger.warning(
            f"Scan {self.scan_id}: Engine '{engine_name}' failed - {error}"
        )

    async def on_finding(self, finding: Any) -> None:
        logger.debug(f"Scan {self.scan_id}: New finding - {finding}")

    async def on_progress(
        self, progress_percent: int, message: Optional[str] = None
    ) -> None:
        logger.debug(
            f"Scan {self.scan_id}: Progress {progress_percent}% - {message}"
        )

    async def on_scan_complete(
        self, findings_count: int, duration_seconds: float
    ) -> None:
        logger.info(
            f"Scan {self.scan_id}: Completed - {findings_count} findings "
            f"in {duration_seconds:.2f}s"
        )

    async def on_scan_failed(self, error: str) -> None:
        logger.error(f"Scan {self.scan_id}: Failed - {error}")

    async def on_warning(self, message: str) -> None:
        logger.warning(f"Scan {self.scan_id}: Warning - {message}")
