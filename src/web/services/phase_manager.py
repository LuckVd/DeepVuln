"""Phase manager for scan phase state management.

P11-02: This module provides the PhaseManager service that manages
the lifecycle and state transitions of scan phases, including status
tracking, phase switching, failure handling, and retry logic.
"""

import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from src.web.models.database import get_session_local
from src.web.models.scan import Scan, ScanPhase, ScanStatus, ScanType, PhaseName
from src.web.repositories.scan import ScanRepository
from src.web.repositories.event import ScanPhaseRepository


logger = logging.getLogger(__name__)


# ============================================================================
# Data Models
# ============================================================================


class PhaseStatus(str, Enum):
    """Phase status constants."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class PhaseTransition(BaseModel):
    """Result of a phase transition attempt.

    Attributes:
        success: Whether the transition succeeded
        from_status: Original status before transition
        to_status: Target status after transition
        message: Human-readable message about the transition
        error: Optional error message if transition failed
    """
    success: bool = Field(description="Whether transition succeeded")
    from_status: Optional[str] = Field(None, description="Original status")
    to_status: str = Field(description="Target status")
    message: str = Field(description="Transition message")
    error: Optional[str] = Field(None, description="Error message if failed")


class PhaseInfo(BaseModel):
    """Detailed information about a phase.

    Attributes:
        phase_name: Name of the phase
        status: Current status
        progress_percent: Phase completion percentage (0-100)
        started_at: When the phase started
        completed_at: When the phase completed (if completed)
        duration_seconds: How long the phase took (if completed)
        files_processed: Number of files processed
        findings_found: Number of findings found
        tokens_used: Tokens consumed
        error_message: Error message if failed
    """
    phase_name: str = Field(description="Phase name")
    status: str = Field(description="Current status")
    progress_percent: int = Field(0, ge=0, le=100, description="Progress percentage")
    started_at: Optional[datetime] = Field(None, description="Start time")
    completed_at: Optional[datetime] = Field(None, description="Completion time")
    duration_seconds: Optional[int] = Field(None, description="Duration in seconds")
    files_processed: int = Field(0, description="Files processed")
    findings_found: int = Field(0, description="Findings found")
    tokens_used: int = Field(0, description="Tokens used")
    error_message: Optional[str] = Field(None, description="Error message")


# ============================================================================
# Phase Order Configuration
# ============================================================================

# Define the standard phase order for different scan types
PHASE_ORDER = {
    ScanType.FULL: [
        PhaseName.L1_PREPARATION,
        PhaseName.L1_ATTACK_SURFACE,
        PhaseName.L2_SEMGREP,
        PhaseName.L2_CODEQL,
        PhaseName.L3_AGENT,
        PhaseName.L3_ADJUDICATION,
        PhaseName.REPORT_GENERATION,
    ],
    ScanType.BASE: [
        PhaseName.L1_PREPARATION,
        PhaseName.L1_ATTACK_SURFACE,
        PhaseName.L2_SEMGREP,
        PhaseName.L2_CODEQL,
        PhaseName.L3_AGENT,
        PhaseName.L3_ADJUDICATION,
        PhaseName.REPORT_GENERATION,
    ],
    ScanType.INCREMENTAL: [
        PhaseName.L1_PREPARATION,
        PhaseName.L1_ATTACK_SURFACE,
        PhaseName.L2_SEMGREP,
        PhaseName.L3_AGENT,
        PhaseName.REPORT_GENERATION,
    ],
}

# Valid state transitions
VALID_TRANSITIONS = {
    PhaseStatus.PENDING: {PhaseStatus.RUNNING, PhaseStatus.SKIPPED},
    PhaseStatus.RUNNING: {PhaseStatus.COMPLETED, PhaseStatus.FAILED, PhaseStatus.PENDING},
    PhaseStatus.FAILED: {PhaseStatus.PENDING, PhaseStatus.SKIPPED},
    PhaseStatus.COMPLETED: set(),  # Terminal state
    PhaseStatus.SKIPPED: set(),  # Terminal state
}


# ============================================================================
# Phase Manager Service
# ============================================================================

class PhaseManager:
    """Service for managing scan phase lifecycle.

    This service provides:
    1. Getting phase status
    2. Starting phases with state validation
    3. Completing phases with output capture
    4. Failing phases with error handling
    5. Skipping phases with reason tracking
    6. Determining next phase in sequence
    7. Validating resume capability
    """

    def __init__(self):
        """Initialize phase manager."""
        self.scan_repo = ScanRepository()
        self.phase_repo = ScanPhaseRepository()

    async def get_phase_status(
        self,
        scan_id: int,
        phase_name: str,
    ) -> Optional[PhaseInfo]:
        """Get detailed status of a specific phase.

        Args:
            scan_id: ID of the scan
            phase_name: Name of the phase

        Returns:
            PhaseInfo with phase details, or None if not found
        """
        try:
            async with get_session_local() as db:
                phase = await self.phase_repo.get_by_name(
                    db,
                    scan_id=scan_id,
                    phase_name=phase_name,
                )
                if phase is None:
                    return None

                # Calculate duration if completed
                duration = None
                if phase.started_at and phase.completed_at:
                    duration = int(
                        (phase.completed_at - phase.started_at).total_seconds()
                    )

                return PhaseInfo(
                    phase_name=phase.phase_name,
                    status=phase.status,
                    progress_percent=phase.progress_percent,
                    started_at=phase.started_at,
                    completed_at=phase.completed_at,
                    duration_seconds=duration,
                    files_processed=phase.files_processed,
                    findings_found=phase.findings_found,
                    tokens_used=phase.tokens_used,
                    error_message=phase.error_message,
                )

        except Exception as e:
            logger.exception(f"Failed to get phase status: {e}")
            return None

    async def start_phase(
        self,
        scan_id: int,
        phase_name: str,
    ) -> PhaseTransition:
        """Start a phase.

        Args:
            scan_id: ID of the scan
            phase_name: Name of the phase to start

        Returns:
            PhaseTransition with result
        """
        try:
            async with get_session_local() as db:
                phase = await self.phase_repo.get_by_name(
                    db,
                    scan_id=scan_id,
                    phase_name=phase_name,
                )

                if phase is None:
                    return PhaseTransition(
                        success=False,
                        to_status=PhaseStatus.RUNNING,
                        message=f"Phase {phase_name} not found for scan {scan_id}",
                        error="Phase not found",
                    )

                from_status = phase.status

                # Check if transition is valid
                if from_status not in VALID_TRANSITIONS:
                    return PhaseTransition(
                        success=False,
                        from_status=from_status,
                        to_status=PhaseStatus.RUNNING,
                        message=f"Cannot start phase from {from_status}",
                        error=f"Invalid current status: {from_status}",
                    )

                if PhaseStatus.RUNNING not in VALID_TRANSITIONS.get(from_status, set()):
                    return PhaseTransition(
                        success=False,
                        from_status=from_status,
                        to_status=PhaseStatus.RUNNING,
                        message=f"Cannot transition from {from_status} to running",
                        error="Invalid transition",
                    )

                # Update phase
                now = datetime.now(timezone.utc)
                phase.status = PhaseStatus.RUNNING
                phase.started_at = phase.started_at or now
                phase.progress_percent = 0

                db.add(phase)
                await db.flush()

                await db.commit()

                logger.info(f"Started phase {phase_name} for scan {scan_id}")
                return PhaseTransition(
                    success=True,
                    from_status=from_status,
                    to_status=PhaseStatus.RUNNING,
                    message=f"Phase {phase_name} started",
                )

        except Exception as e:
            logger.exception(f"Failed to start phase {phase_name}: {e}")
            return PhaseTransition(
                success=False,
                to_status=PhaseStatus.RUNNING,
                message=f"Failed to start phase: {e}",
                error=str(e),
            )

    async def complete_phase(
        self,
        scan_id: int,
        phase_name: str,
        output: Dict[str, Any],
    ) -> PhaseTransition:
        """Complete a phase with output.

        Args:
            scan_id: ID of the scan
            phase_name: Name of the phase
            output: Output data from the phase

        Returns:
            PhaseTransition with result
        """
        try:
            async with get_session_local() as db:
                phase = await self.phase_repo.get_by_name(
                    db,
                    scan_id=scan_id,
                    phase_name=phase_name,
                )

                if phase is None:
                    return PhaseTransition(
                        success=False,
                        to_status=PhaseStatus.COMPLETED,
                        message=f"Phase {phase_name} not found",
                        error="Phase not found",
                    )

                from_status = phase.status

                # Must be running to complete
                if from_status != PhaseStatus.RUNNING:
                    return PhaseTransition(
                        success=False,
                        from_status=from_status,
                        to_status=PhaseStatus.COMPLETED,
                        message=f"Cannot complete phase from {from_status}",
                        error="Phase not running",
                    )

                # Update phase
                now = datetime.now(timezone.utc)
                phase.status = PhaseStatus.COMPLETED
                phase.completed_at = now
                phase.progress_percent = 100
                phase.output_data = output

                # Extract stats from output
                if output:
                    phase.files_processed = output.get("files_processed", 0)
                    phase.findings_found = output.get("findings_found", 0)
                    phase.tokens_used = output.get("tokens_used", 0)
                    phase.output_path = output.get("output_path")

                db.add(phase)
                await db.flush()

                # Update scan progress
                scan = await self.scan_repo.get(db, id=scan_id)
                if scan:
                    scan.engines_completed = (scan.engines_completed or 0) + 1
                    db.add(scan)

                await db.commit()

                logger.info(
                    f"Completed phase {phase_name} for scan {scan_id} "
                    f"({phase.findings_found} findings)"
                )
                return PhaseTransition(
                    success=True,
                    from_status=from_status,
                    to_status=PhaseStatus.COMPLETED,
                    message=f"Phase {phase_name} completed",
                )

        except Exception as e:
            logger.exception(f"Failed to complete phase {phase_name}: {e}")
            return PhaseTransition(
                success=False,
                to_status=PhaseStatus.COMPLETED,
                message=f"Failed to complete phase: {e}",
                error=str(e),
            )

    async def fail_phase(
        self,
        scan_id: int,
        phase_name: str,
        error: str,
    ) -> PhaseTransition:
        """Mark a phase as failed.

        Args:
            scan_id: ID of the scan
            phase_name: Name of the phase
            error: Error message describing the failure

        Returns:
            PhaseTransition with result
        """
        try:
            async with get_session_local() as db:
                phase = await self.phase_repo.get_by_name(
                    db,
                    scan_id=scan_id,
                    phase_name=phase_name,
                )

                if phase is None:
                    return PhaseTransition(
                        success=False,
                        to_status=PhaseStatus.FAILED,
                        message=f"Phase {phase_name} not found",
                        error="Phase not found",
                    )

                from_status = phase.status

                # Can fail from running or pending
                if from_status not in {PhaseStatus.RUNNING, PhaseStatus.PENDING}:
                    return PhaseTransition(
                        success=False,
                        from_status=from_status,
                        to_status=PhaseStatus.FAILED,
                        message=f"Cannot fail phase from {from_status}",
                        error="Invalid transition",
                    )

                # Update phase
                phase.status = PhaseStatus.FAILED
                phase.error_message = error

                db.add(phase)
                await db.flush()
                await db.commit()

                logger.warning(f"Phase {phase_name} failed for scan {scan_id}: {error}")
                return PhaseTransition(
                    success=True,
                    from_status=from_status,
                    to_status=PhaseStatus.FAILED,
                    message=f"Phase {phase_name} failed: {error}",
                )

        except Exception as e:
            logger.exception(f"Failed to mark phase {phase_name} as failed: {e}")
            return PhaseTransition(
                success=False,
                to_status=PhaseStatus.FAILED,
                message=f"Failed to update phase: {e}",
                error=str(e),
            )

    async def skip_phase(
        self,
        scan_id: int,
        phase_name: str,
        reason: str,
    ) -> PhaseTransition:
        """Skip a phase.

        Args:
            scan_id: ID of the scan
            phase_name: Name of the phase
            reason: Reason for skipping

        Returns:
            PhaseTransition with result
        """
        try:
            async with get_session_local() as db:
                phase = await self.phase_repo.get_by_name(
                    db,
                    scan_id=scan_id,
                    phase_name=phase_name,
                )

                if phase is None:
                    return PhaseTransition(
                        success=False,
                        to_status=PhaseStatus.SKIPPED,
                        message=f"Phase {phase_name} not found",
                        error="Phase not found",
                    )

                from_status = phase.status

                # Can only skip pending or failed phases
                if from_status not in {PhaseStatus.PENDING, PhaseStatus.FAILED}:
                    return PhaseTransition(
                        success=False,
                        from_status=from_status,
                        to_status=PhaseStatus.SKIPPED,
                        message=f"Cannot skip phase from {from_status}",
                        error="Invalid transition",
                    )

                # Update phase
                now = datetime.now(timezone.utc)
                phase.status = PhaseStatus.SKIPPED
                phase.completed_at = now
                phase.error_message = f"Skipped: {reason}"

                db.add(phase)
                await db.flush()

                # Update scan progress
                scan = await self.scan_repo.get(db, id=scan_id)
                if scan:
                    scan.engines_completed = (scan.engines_completed or 0) + 1
                    db.add(scan)

                await db.commit()

                logger.info(f"Skipped phase {phase_name} for scan {scan_id}: {reason}")
                return PhaseTransition(
                    success=True,
                    from_status=from_status,
                    to_status=PhaseStatus.SKIPPED,
                    message=f"Phase {phase_name} skipped: {reason}",
                )

        except Exception as e:
            logger.exception(f"Failed to skip phase {phase_name}: {e}")
            return PhaseTransition(
                success=False,
                to_status=PhaseStatus.SKIPPED,
                message=f"Failed to skip phase: {e}",
                error=str(e),
            )

    async def get_next_phase(
        self,
        scan_id: int,
    ) -> Optional[str]:
        """Get the next phase to execute for a scan.

        Args:
            scan_id: ID of the scan

        Returns:
            Name of next phase, or None if all phases complete
        """
        try:
            async with get_session_local() as db:
                scan = await self.scan_repo.get(db, id=scan_id)
                if scan is None:
                    return None

                # Get phase order for scan type
                phase_order = PHASE_ORDER.get(scan.scan_type, PHASE_ORDER[ScanType.FULL])

                # Get all phases for this scan
                phases = await self.phase_repo.get_by_scan(db, scan_id=scan_id)
                phase_status_map = {p.phase_name: p.status for p in phases}

                # Find next pending phase
                for phase_name in phase_order:
                    status = phase_status_map.get(phase_name)
                    if status in {PhaseStatus.PENDING.value, None}:
                        return phase_name
                    elif status == PhaseStatus.FAILED.value:
                        # Retry failed phase
                        return phase_name

                return None

        except Exception as e:
            logger.exception(f"Failed to get next phase: {e}")
            return None

    async def can_resume_from(
        self,
        scan_id: int,
        phase_name: str,
    ) -> bool:
        """Check if a scan can resume from a specific phase.

        Args:
            scan_id: ID of the scan
            phase_name: Name of the phase to resume from

        Returns:
            True if resuming is possible, False otherwise
        """
        try:
            async with get_session_local() as db:
                # Get the phase to resume from
                phase = await self.phase_repo.get_by_name(
                    db,
                    scan_id=scan_id,
                    phase_name=phase_name,
                )

                if phase is None:
                    return False

                # Can resume if phase was running or failed
                return phase.status in {
                    PhaseStatus.RUNNING.value,
                    PhaseStatus.FAILED.value,
                }

        except Exception as e:
            logger.exception(f"Failed to check resume capability: {e}")
            return False


# ============================================================================
# Singleton Instance
# ============================================================================

_phase_manager: Optional[PhaseManager] = None


def get_phase_manager() -> PhaseManager:
    """Get or create phase manager instance.

    Returns:
        PhaseManager singleton instance
    """
    global _phase_manager
    if _phase_manager is None:
        _phase_manager = PhaseManager()
    return _phase_manager
