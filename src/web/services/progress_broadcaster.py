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


def _sanitize_for_json(obj: Any) -> Any:
    """Recursively convert non-JSON-serializable types to safe values."""
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if isinstance(obj, (list, tuple)):
        return [_sanitize_for_json(item) for item in obj]
    if isinstance(obj, dict):
        return {str(k): _sanitize_for_json(v) for k, v in obj.items()}
    # Enums, Path, etc. → str
    return str(obj)


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
        self, findings_count: int, duration_seconds: float, **kwargs: Any
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

        # Base phase weights (all 9 phases)
        # adversarial_verification 是 engine_execution 的两倍
        self.base_phase_weights = {
            "l1_preparation": 3,
            "source_preparation": 3,
            "engine_selection": 2,
            "engine_execution": 25,
            "exploitability_verification": 5,
            "deduplication_adjudication": 7,
            "adversarial_verification": 50,  # engine_execution 的两倍
            "result_merging": 3,
            "token_statistics": 2,
        }

        # Optional phases (may be skipped based on config)
        self.optional_phases = {
            "exploitability_verification",
            "adversarial_verification",
        }

        # Scan configuration for optional phase handling
        self.scan_config: Dict[str, Any] = {}

        # Current effective weights (dynamically calculated)
        self.phase_weights = self.base_phase_weights.copy()
        self.current_phase: Optional[str] = None
        self.phase_start_time: Optional[datetime] = None

        # Track completed phases for cumulative progress
        self._completed_phases: set = set()

        # Fine-grained phase-internal progress tracking.
        # Maps phase_name -> float (0.0 ~ 1.0) representing how far
        # the *current* phase has progressed internally.
        self._phase_internal_progress: Dict[str, float] = {}

        # Counters used to derive internal progress for specific phases
        self._engines_started: int = 0
        self._engines_completed: int = 0
        self._adversarial_findings_total: int = 0
        self._adversarial_findings_done: int = 0

    def _get_db_session(self) -> AsyncSession:
        """Get a new database session."""
        return self.db_session_factory()

    def set_scan_config(self, config: Dict[str, Any]) -> None:
        """Set scan configuration for optional phase handling.

        Args:
            config: Scan configuration dictionary
        """
        self.scan_config = config
        # Recalculate effective weights based on config
        self.phase_weights = self._calculate_effective_weights()

    def _get_active_phases(self) -> set:
        """Get phases that are active based on scan config.

        Returns:
            Set of active phase names
        """
        active = set(self.base_phase_weights.keys())

        # Check exploitability_verification (llm_verify defaults to True)
        if not self.scan_config.get("llm_verify", True):
            active.discard("exploitability_verification")

        # Check adversarial_verification (adversarial defaults to False)
        if not self.scan_config.get("adversarial", False):
            active.discard("adversarial_verification")

        return active

    def _calculate_effective_weights(self) -> Dict[str, int]:
        """Calculate effective weights based on active phases.

        When optional phases are disabled, redistributes their weights
        proportionally to other active phases.

        Returns:
            Dictionary mapping phase names to effective weights
        """
        active = self._get_active_phases()

        # Calculate total weight of active phases
        total_weight = sum(
            self.base_phase_weights.get(phase, 0)
            for phase in active
        )

        # If total is 100, return base weights directly
        if total_weight == 100:
            return self.base_phase_weights.copy()

        # Otherwise scale proportionally
        scale = 100 / total_weight
        effective = {}
        for phase in active:
            effective[phase] = int(self.base_phase_weights[phase] * scale)

        return effective

    async def on_phase_start(self, phase_name: str, **data: Any) -> None:
        """Handle phase start event.

        Creates a ScanPhase record and broadcasts to WebSocket.
        """
        self.current_phase = phase_name
        self.phase_start_time = _utc_now_naive()

        # Persist event to database
        await self._create_event(
            event_type="phase_start",
            message=f"Phase '{phase_name}' started",
            event_level="info",
            details={"phase": phase_name, **data},
        )

        async with self._get_db_session() as db:
            from sqlalchemy import select, update

            # Check if there's already a running phase with the same name
            existing_query = (
                select(ScanPhase)
                .where(ScanPhase.scan_id == self.scan_id)
                .where(ScanPhase.phase_name == phase_name)
                .where(ScanPhase.status == "running")
            )
            existing = await db.execute(existing_query)
            existing_phase = existing.scalar_one_or_none()

            if existing_phase:
                # Update the start time of the existing phase
                await db.execute(
                    update(ScanPhase)
                    .where(ScanPhase.id == existing_phase.id)
                    .values(started_at=self.phase_start_time)
                )
            else:
                # Create new phase record
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

        # Update scan current phase and progress
        await self._update_scan({
            "current_phase": phase_name,
            "progress_percent": self._calculate_progress()
        })

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

        # Prepare scan update data (collect all phase data before DB update)
        scan_update_data = {}

        # Update total_files from source_preparation phase
        if phase_name == "source_preparation" and "total_files" in result:
            scan_update_data["total_files"] = result["total_files"]
            logger.info(f"Scan {self.scan_id}: Total files set to {result['total_files']} from source_preparation phase")
        elif phase_name == "source_preparation":
            logger.warning(f"Scan {self.scan_id}: source_preparation phase completed but 'total_files' not in result. Result keys: {list(result.keys())}")

        async with self._get_db_session() as db:
            # Find and update the phase record
            from sqlalchemy import select, update

            # Get all running phases with this name (there may be duplicates)
            phase_query = (
                select(ScanPhase)
                .where(ScanPhase.scan_id == self.scan_id)
                .where(ScanPhase.phase_name == phase_name)
                .where(ScanPhase.status == "running")
                .order_by(ScanPhase.started_at.desc())
            )

            phase_result = await db.execute(phase_query)
            phases = phase_result.scalars().all()

            if phases:
                # Update the most recent one (first in descending order)
                phase = phases[0]
                await db.execute(
                    update(ScanPhase)
                    .where(ScanPhase.id == phase.id)
                    .values(
                        status="completed",
                        completed_at=_utc_now_naive(),
                        duration_seconds=round(duration_seconds, 2),
                        findings_found=result.get("findings", 0),
                        tokens_used=result.get("tokens_used", 0),
                    )
                )
                # Mark any other running phases with the same name as skipped
                if len(phases) > 1:
                    for duplicate in phases[1:]:
                        await db.execute(
                            update(ScanPhase)
                            .where(ScanPhase.id == duplicate.id)
                            .values(status="skipped")
                        )
                await db.commit()

        # Update scan record with progress
        scan_update_data["progress_percent"] = self._calculate_progress()
        await self._update_scan(scan_update_data)

        # Persist event to database (with full result data for terminal replay)
        phase_result_details = {
            "phase": phase_name,
            "duration_seconds": round(duration_seconds, 2),
            "findings": result.get("findings", 0),
            "tokens_used": result.get("tokens_used", 0),
        }
        # Forward selected result fields for terminal display
        for key in (
            "total_files", "languages", "frameworks", "attack_surface",
            "engines", "verified_findings", "unique_findings",
            "duplicates_removed", "confirmed", "rejected",
            "total_findings", "total_tokens", "estimated_cost",
            "per_engine_details", "severity_breakdown", "per_phase_tokens",
            "file_counts", "primary_language",
        ):
            if key in result:
                phase_result_details[key] = result[key]
        await self._create_event(
            event_type="phase_complete",
            message=f"Phase '{phase_name}' completed in {duration_seconds:.1f}s",
            event_level="info",
            details=phase_result_details,
        )

        # Broadcast to WebSocket
        await self.event_broadcaster.broadcast_phase_complete(
            self.scan_id,
            phase_name,
            duration_seconds,
            findings=result.get("findings", 0),
            tokens_used=result.get("tokens_used", 0),
            result=result,
        )

        logger.debug(
            f"Phase '{phase_name}' completed for scan {self.scan_id} "
            f"in {duration_seconds:.2f}s"
        )

    async def on_engine_start(self, engine_name: str) -> None:
        """Handle engine start event."""
        self._engines_started += 1
        # Update engine_execution internal progress
        if self._engines_started > 0:
            self._phase_internal_progress["engine_execution"] = (
                self._engines_completed / self._engines_started
            )
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
        """Handle engine complete event.

        Updates real-time statistics including findings count and tokens used.
        """
        self._engines_completed += 1
        # Update engine_execution internal progress
        if self._engines_started > 0:
            self._phase_internal_progress["engine_execution"] = (
                self._engines_completed / self._engines_started
            )

        # Get all stats in a single DB session (consolidated from 3 queries to 1 session)
        stats = await self._get_engine_complete_stats()

        # Real-time update of scan statistics
        await self._update_scan(
            {
                "findings_count": stats["total_findings"],
                "tokens_used": stats["tokens_used"],
                "critical_count": stats["critical"],
                "high_count": stats["high"],
                "medium_count": stats["medium"],
                "low_count": stats["low"],
                "info_count": stats["info"],
                "verified_count": stats["verified"],
                "false_positive_count": stats["false_positive"],
            }
        )

        # Create event in database
        await self._create_event(
            event_type="engine_complete",
            message=f"Engine '{engine_name}' completed with {findings_count} findings",
            engine_name=engine_name,
            details={
                "findings_count": findings_count,
                "duration_seconds": duration_seconds,
                "total_findings": stats["total_findings"],
                "tokens_used": stats["tokens_used"],
            },
        )

        # Broadcast to WebSocket
        await self.event_broadcaster.broadcast_scan_progress(
            self.scan_id,
            progress_percent=self._calculate_progress(),
            message=f"{engine_name} analysis complete: {findings_count} findings",
        )

        logger.info(
            f"Engine '{engine_name}' completed for scan {self.scan_id}: "
            f"{findings_count} findings (total: {stats['total_findings']}), {stats['tokens_used']} tokens"
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

        # Persist event to database (best-effort, must not crash the scan)
        try:
            sanitized = _sanitize_for_json(finding_data)
            await self._create_event(
                event_type="finding",
                message=f"New finding: {finding_data.get('title', 'Unknown')}",
                event_level="info",
                details=sanitized,
            )
        except Exception as e:
            logger.warning(f"Failed to persist finding event: {e}")

        # Broadcast to WebSocket
        await self.event_broadcaster.broadcast_finding(
            self.scan_id, finding_data
        )

    async def on_progress(
        self,
        progress_percent: int,
        message: Optional[str] = None,
        phase_name: Optional[str] = None,
    ) -> None:
        """Handle progress update event.

        Args:
            progress_percent: Overall progress 0-100, or phase-internal 0-100
                when *phase_name* is given.
            message: Optional status message.
            phase_name: If given, treat progress_percent as the internal
                progress (0-100) for this specific phase rather than the
                overall scan progress.
        """
        if phase_name:
            # Store as phase-internal progress (0.0 ~ 1.0)
            self._phase_internal_progress[phase_name] = min(
                progress_percent / 100.0, 1.0
            )
            # Recalculate overall progress from weights + internal progress
            progress_percent = self._calculate_progress()

        # Update scan record
        await self._update_scan({"progress_percent": progress_percent})

        # Broadcast to WebSocket
        await self.event_broadcaster.broadcast_scan_progress(
            self.scan_id,
            progress_percent=progress_percent,
            message=message,
        )

    async def _calculate_severity_stats(self) -> Dict[str, int]:
        """Calculate severity statistics from findings in the database.

        Uses COUNT+GROUP BY to avoid the default limit=100 in
        FindingRepository.get_by_scan(), ensuring all findings are counted.
        """
        from sqlalchemy import select, func

        stats: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0,
            "info": 0, "verified": 0, "false_positive": 0,
        }
        async with self._get_db_session() as db:
            sev_result = await db.execute(
                select(Finding.severity, func.count(Finding.id))
                .where(Finding.scan_id == self.scan_id)
                .group_by(Finding.severity)
            )
            for severity, count in sev_result.all():
                sev_lower = (severity or "info").lower()
                if sev_lower in stats:
                    stats[sev_lower] += count
                else:
                    stats["info"] += count

            # Count verified / false_positive by status
            status_result = await db.execute(
                select(Finding.status, func.count(Finding.id))
                .where(Finding.scan_id == self.scan_id)
                .group_by(Finding.status)
            )
            for status_val, count in status_result.all():
                status_lower = (status_val or "").lower()
                if status_lower == "verified":
                    stats["verified"] += count
                elif status_lower == "false_positive":
                    stats["false_positive"] += count

        return stats

    async def _get_total_tokens_used(self) -> int:
        """Get total tokens used from scan record."""
        async with self._get_db_session() as db:
            scan = await self.scan_repo.get(db, id=self.scan_id)
            return scan.tokens_used if scan else 0

    async def on_scan_complete(
        self, findings_count: int, duration_seconds: float, tokens_used: int = 0,
        severity_breakdown: Optional[Dict[str, int]] = None,
        per_phase_tokens: Optional[Dict[str, int]] = None,
        agent_analyzed_files: Optional[list] = None,
        agent_files_analyzed: int = 0,
    ) -> None:
        """Handle scan complete event."""
        # Calculate severity statistics
        severity_stats = severity_breakdown or await self._calculate_severity_stats()

        # Get total tokens used from events, use max of passed-in and DB value
        db_tokens = await self._get_total_tokens_used()
        tokens_used = max(tokens_used, db_tokens)

        # Get current scan to access total_files
        async with self._get_db_session() as db:
            scan = await self.scan_repo.get(db, id=self.scan_id)
            if scan:
                total_files = scan.total_files or 0
            else:
                total_files = 0

        # Update scan record with all statistics
        update_data = {
            "status": ScanStatus.COMPLETED,
            "progress_percent": 100,
            "findings_count": findings_count,
            "completed_at": _utc_now_naive(),
            "critical_count": severity_stats["critical"],
            "high_count": severity_stats["high"],
            "medium_count": severity_stats["medium"],
            "low_count": severity_stats["low"],
            "info_count": severity_stats["info"],
            "verified_count": severity_stats.get("verified", 0),
            "false_positive_count": severity_stats.get("false_positive", 0),
            "current_phase": None,  # Clear current phase on completion
            "current_step": None,   # Clear current step on completion
        }

        # Set analyzed_files to actual agent-analyzed count
        update_data["analyzed_files"] = agent_files_analyzed or 0

        # Store agent analyzed file paths in scan config
        if agent_analyzed_files:
            async with self._get_db_session() as db:
                scan = await self.scan_repo.get(db, id=self.scan_id)
                if scan and isinstance(scan.config, dict):
                    scan_config = {**scan.config, "agent_analyzed_files": agent_analyzed_files}
                    update_data["config"] = scan_config
                elif scan:
                    update_data["config"] = {"agent_analyzed_files": agent_analyzed_files}

        await self._update_scan(update_data)

        # Broadcast to WebSocket
        await self.event_broadcaster.broadcast_scan_complete(
            self.scan_id, findings_count, duration_seconds, tokens_used,
            severity_breakdown=severity_stats,
            per_phase_tokens=per_phase_tokens,
        )

        # Create completion event
        await self._create_event(
            event_type="scan_complete",
            message=f"Scan completed with {findings_count} findings",
            details={
                "findings_count": findings_count,
                "duration_seconds": duration_seconds,
                "tokens_used": tokens_used,
                "severity_breakdown": severity_stats,
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
        # Create warning event in database
        await self._create_event(
            event_type="warning",
            message=message,
            event_level="warning",
        )

        # Broadcast to WebSocket
        await self.event_broadcaster.broadcast_event(
            self.scan_id,
            event_type="warning",
            data={"message": message},
        )

        logger.warning(f"Scan {self.scan_id} warning: {message}")

    async def broadcast_event(
        self,
        event_type: str,
        data: Dict[str, Any],
    ) -> None:
        """Broadcast a custom event via WebSocket and persist to database.

        Used for ad-hoc events like adversarial verification rounds,
        agent conversation turns, file progress updates, etc.

        Args:
            event_type: Custom event type string
            data: Event payload
        """
        # Persist custom event to database (best-effort)
        try:
            await self._create_event(
                event_type=event_type,
                message=data.get("message") or data.get("finding_title") or f"Event: {event_type}",
                event_level="info",
                details=_sanitize_for_json(data),
            )
        except Exception as e:
            logger.warning(f"Failed to persist event '{event_type}': {e}")

        await self.event_broadcaster.broadcast_event(
            self.scan_id,
            event_type=event_type,
            data=data,
        )

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
        """Calculate overall progress based on completed phases and internal progress.

        Uses dynamic weights that adjust based on which optional phases
        are enabled in the scan configuration.  For the currently running
        phase the internal progress (0.0-1.0) is used instead of a
        hardcoded 50%.

        Returns:
            Progress percentage (0-100)
        """
        # Get currently active phases
        active_phases = self._get_active_phases()

        # Phase order for progress calculation (all 9 phases)
        phase_order = [
            "l1_preparation",
            "source_preparation",
            "engine_selection",
            "engine_execution",
            "exploitability_verification",
            "deduplication_adjudication",
            "adversarial_verification",
            "result_merging",
            "token_statistics",
        ]

        total_weight = sum(self.phase_weights.values())
        completed_weight = 0

        for phase in phase_order:
            # Skip inactive phases
            if phase not in active_phases:
                continue

            if phase in self._completed_phases:
                completed_weight += self.phase_weights.get(phase, 0)
            elif phase == self.current_phase:
                # Use fine-grained internal progress if available,
                # otherwise fall back to a conservative 10%
                internal = self._phase_internal_progress.get(phase, 0.1)
                completed_weight += self.phase_weights.get(phase, 0) * internal
                break

        return int((completed_weight / total_weight * 100)) if total_weight > 0 else 0

    async def _get_engine_complete_stats(self) -> Dict[str, Any]:
        """Get all stats needed for engine complete in a single DB session.

        Returns:
            Dictionary with tokens_used, total_findings, severity stats
        """
        from sqlalchemy import select, func

        stats: Dict[str, Any] = {
            "tokens_used": 0,
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "verified": 0,
            "false_positive": 0,
        }

        async with self._get_db_session() as db:
            # Query 1: Tokens + findings from phases (single query)
            phase_result = await db.execute(
                select(
                    func.sum(ScanPhase.tokens_used),
                    func.sum(ScanPhase.findings_found),
                ).where(ScanPhase.scan_id == self.scan_id)
            )
            row = phase_result.one_or_none()
            if row:
                stats["tokens_used"] = row[0] or 0
                stats["total_findings"] = row[1] or 0

            # Query 2: Severity stats from findings
            sev_result = await db.execute(
                select(
                    Finding.severity,
                    Finding.status,
                    func.count(Finding.id),
                ).where(Finding.scan_id == self.scan_id).group_by(Finding.severity, Finding.status)
            )
            for severity, status, count in sev_result.all():
                severity_lower = (severity or "").lower()
                if severity_lower in stats:
                    stats[severity_lower] += count
                status_lower = (status or "").lower()
                if status_lower == "verified":
                    stats["verified"] += count
                elif status_lower == "false_positive":
                    stats["false_positive"] += count

        return stats


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
        self, findings_count: int, duration_seconds: float, **kwargs: Any
    ) -> None:
        logger.info(
            f"Scan {self.scan_id}: Completed - {findings_count} findings "
            f"in {duration_seconds:.2f}s"
        )

    async def on_scan_failed(self, error: str) -> None:
        logger.error(f"Scan {self.scan_id}: Failed - {error}")

    async def on_warning(self, message: str) -> None:
        logger.warning(f"Scan {self.scan_id}: Warning - {message}")
