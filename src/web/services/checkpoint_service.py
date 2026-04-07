"""Checkpoint service for pause/resume functionality.

P11-01: This module provides the CheckpointService that manages
scan checkpoint data, including saving, loading, validation, and cleanup.
It enables scan tasks to be paused and resumed from their last state.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from src.web.models.database import get_session_local
from src.web.models.scan import Scan, ScanPhase, ScanStatus, PhaseName
from src.web.repositories.scan import ScanRepository
from src.web.repositories.event import ScanPhaseRepository


logger = logging.getLogger(__name__)


# ============================================================================
# Data Models
# ============================================================================


class PhaseCheckpoint(BaseModel):
    """Checkpoint data for a single scan phase.

    Attributes:
        status: Current status of the phase
        output_path: Optional path to phase output file
        output_data: Optional phase output data (for reuse)
        error_message: Optional error message if phase failed
        started_at: When the phase started
        completed_at: When the phase completed (if completed)
        files_processed: Number of files processed in this phase
        findings_found: Number of findings found in this phase
        tokens_used: Tokens consumed in this phase
    """
    status: str = Field(description="Phase status: pending/running/completed/failed/skipped")
    output_path: Optional[str] = Field(None, description="Path to phase output file")
    output_data: Optional[Dict[str, Any]] = Field(None, description="Phase output data")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    started_at: Optional[datetime] = Field(None, description="Phase start time")
    completed_at: Optional[datetime] = Field(None, description="Phase completion time")
    files_processed: int = Field(0, description="Number of files processed")
    findings_found: int = Field(0, description="Number of findings found")
    tokens_used: int = Field(0, description="Tokens consumed")

    @field_validator("status")
    @classmethod
    def validate_status(cls, v):
        """Validate phase status."""
        valid_statuses = {"pending", "running", "completed", "failed", "skipped"}
        if v not in valid_statuses:
            raise ValueError(f"Invalid phase status: {v}")
        return v


class CheckpointData(BaseModel):
    """Complete checkpoint data for a scan.

    Attributes:
        scan_id: ID of the scan
        current_phase: The phase that was in progress when paused
        phases: Dictionary of phase_name -> PhaseCheckpoint
        global_state: Global scan state (config, options, etc.)
        resume_data: Data needed to resume execution
        created_at: When this checkpoint was created
        version: Checkpoint format version for migration
    """
    scan_id: int = Field(description="ID of the scan")
    current_phase: Optional[str] = Field(None, description="Current phase when paused")
    phases: Dict[str, PhaseCheckpoint] = Field(
        default_factory=dict,
        description="Phase checkpoints by phase name"
    )
    global_state: Dict[str, Any] = Field(
        default_factory=dict,
        description="Global scan state"
    )
    resume_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Data needed for resume"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Checkpoint creation time"
    )
    version: str = Field("1.0", description="Checkpoint format version")

    def get_hash(self) -> str:
        """Get hash of checkpoint data for integrity verification."""
        data_str = self.model_dump_json(exclude={"created_at"})
        return hashlib.sha256(data_str.encode()).hexdigest()[:16]


class ResumeStrategy(BaseModel):
    """Strategy for resuming a scan from a checkpoint.

    Attributes:
        can_resume: Whether resuming is possible
        resume_phase: The phase to resume from
        skip_phases: Phases to skip (already completed)
        retry_phases: Phases to retry (failed or incomplete)
        reason: Explanation of the resume strategy
    """
    can_resume: bool = Field(description="Whether resuming is possible")
    resume_phase: Optional[str] = Field(None, description="Phase to resume from")
    skip_phases: List[str] = Field(default_factory=list, description="Phases to skip")
    retry_phases: List[str] = Field(default_factory=list, description="Phases to retry")
    reason: str = Field(description="Explanation of the strategy")


# ============================================================================
# Checkpoint Service
# ============================================================================


class CheckpointService:
    """Service for managing scan checkpoint data.

    This service provides:
    1. Saving checkpoint data to database
    2. Loading checkpoint data from database
    3. Verifying checkpoint integrity
    4. Cleaning up old checkpoints
    5. Determining resume strategy
    """

    def __init__(self):
        """Initialize checkpoint service."""
        self.scan_repo = ScanRepository()
        self.phase_repo = ScanPhaseRepository()
        self._checkpoint_dir: Optional[Path] = None

    def _get_checkpoint_dir(self) -> Path:
        """Get or create checkpoint directory.

        Returns:
            Path to checkpoint directory
        """
        if self._checkpoint_dir is None:
            # Default to /tmp/deepvuln/checkpoints
            checkpoint_path = Path("/tmp/deepvuln/checkpoints")
            checkpoint_path.mkdir(parents=True, exist_ok=True)
            self._checkpoint_dir = checkpoint_path
        return self._checkpoint_dir

    async def save_checkpoint(
        self,
        scan_id: int,
        phase: str,
        data: Dict[str, Any],
    ) -> bool:
        """Save checkpoint data for a scan.

        Args:
            scan_id: ID of the scan
            phase: Current phase name
            data: Checkpoint data to save

        Returns:
            True if save succeeded, False otherwise
        """
        try:
            async with get_session_local() as db:
                scan = await self.scan_repo.get(db, id=scan_id)
                if scan is None:
                    logger.error(f"Scan {scan_id} not found for checkpoint save")
                    return False

                # Build checkpoint data
                checkpoint = CheckpointData(
                    scan_id=scan_id,
                    current_phase=phase,
                    global_state=data.get("global_state", {}),
                    resume_data=data.get("resume_data", {}),
                )

                # Get phase states from database
                phases = await self.phase_repo.get_by_scan(db, scan_id=scan_id)
                for p in phases:
                    phase_checkpoint = PhaseCheckpoint(
                        status=p.status,
                        output_path=p.output_path,
                        output_data=p.output_data,
                        error_message=p.error_message,
                        started_at=p.started_at,
                        completed_at=p.completed_at,
                        files_processed=p.files_processed,
                        findings_found=p.findings_found,
                        tokens_used=p.tokens_used,
                    )
                    checkpoint.phases[p.phase_name] = phase_checkpoint

                # Save to database
                checkpoint_dict = checkpoint.model_dump()
                checkpoint_dict["hash"] = checkpoint.get_hash()

                await self.scan_repo.update(
                    db,
                    db_obj=scan,
                    obj_in={"checkpoint_data": checkpoint_dict}
                )

                # Also save to file as backup for large data
                await self._save_checkpoint_to_file(checkpoint)

                await db.commit()

                logger.info(f"Saved checkpoint for scan {scan_id} at phase {phase}")
                return True

        except Exception as e:
            logger.exception(f"Failed to save checkpoint for scan {scan_id}: {e}")
            return False

    async def load_checkpoint(self, scan_id: int) -> Optional[CheckpointData]:
        """Load checkpoint data for a scan.

        Args:
            scan_id: ID of the scan

        Returns:
            CheckpointData if found, None otherwise
        """
        try:
            async with get_session_local() as db:
                scan = await self.scan_repo.get(db, id=scan_id)
                if scan is None:
                    logger.warning(f"Scan {scan_id} not found for checkpoint load")
                    return None

                if scan.checkpoint_data is None:
                    logger.info(f"No checkpoint data found for scan {scan_id}")
                    return None

                # Validate checkpoint format
                checkpoint_dict = scan.checkpoint_data
                if "version" not in checkpoint_dict:
                    logger.warning(f"Invalid checkpoint format for scan {scan_id}")
                    return None

                # Create CheckpointData from dict
                checkpoint = CheckpointData(**checkpoint_dict)

                # Verify integrity
                stored_hash = checkpoint_dict.get("hash")
                if stored_hash and stored_hash != checkpoint.get_hash():
                    logger.warning(f"Checkpoint hash mismatch for scan {scan_id}")
                    return None

                logger.info(f"Loaded checkpoint for scan {scan_id}")
                return checkpoint

        except Exception as e:
            logger.exception(f"Failed to load checkpoint for scan {scan_id}: {e}")
            return None

    async def verify_checkpoint(self, checkpoint: CheckpointData) -> bool:
        """Verify checkpoint data integrity.

        Args:
            checkpoint: Checkpoint data to verify

        Returns:
            True if checkpoint is valid, False otherwise
        """
        try:
            # Check required fields
            if checkpoint.scan_id <= 0:
                return False

            # Verify phase data
            for phase_name, phase_checkpoint in checkpoint.phases.items():
                if phase_checkpoint.status not in {
                    "pending", "running", "completed", "failed", "skipped"
                }:
                    return False

                # If phase is completed, it should have completion time
                if phase_checkpoint.status == "completed":
                    if phase_checkpoint.completed_at is None:
                        return False

            # Check version compatibility
            if checkpoint.version not in {"1.0"}:
                logger.warning(f"Unsupported checkpoint version: {checkpoint.version}")
                return False

            return True

        except Exception as e:
            logger.exception(f"Checkpoint verification failed: {e}")
            return False

    async def clean_checkpoint(self, scan_id: int) -> bool:
        """Clean checkpoint data for a scan.

        Args:
            scan_id: ID of the scan

        Returns:
            True if cleanup succeeded, False otherwise
        """
        try:
            async with get_session_local() as db:
                scan = await self.scan_repo.get(db, id=scan_id)
                if scan is None:
                    return False

                # Clear database checkpoint
                await self.scan_repo.update(
                    db,
                    db_obj=scan,
                    obj_in={"checkpoint_data": None}
                )

                # Remove file backup
                await self._delete_checkpoint_file(scan_id)

                await db.commit()

                logger.info(f"Cleaned checkpoint for scan {scan_id}")
                return True

        except Exception as e:
            logger.exception(f"Failed to clean checkpoint for scan {scan_id}: {e}")
            return False

    async def get_resume_strategy(
        self,
        checkpoint: CheckpointData,
    ) -> ResumeStrategy:
        """Determine the optimal resume strategy from a checkpoint.

        Args:
            checkpoint: Checkpoint data to analyze

        Returns:
            ResumeStrategy with recommended actions
        """
        try:
            skip_phases = []
            retry_phases = []
            resume_phase = None

            # Analyze each phase
            for phase_name, phase_checkpoint in checkpoint.phases.items():
                if phase_checkpoint.status == "completed":
                    skip_phases.append(phase_name)
                elif phase_checkpoint.status in {"failed", "running"}:
                    retry_phases.append(phase_name)

            # Determine resume phase
            if checkpoint.current_phase:
                current_status = checkpoint.phases.get(
                    checkpoint.current_phase
                )
                if current_status and current_status.status in {"running", "failed"}:
                    resume_phase = checkpoint.current_phase
                else:
                    # Find next pending phase
                    phase_order = [
                        PhaseName.L1_PREPARATION,
                        PhaseName.L1_ATTACK_SURFACE,
                        PhaseName.L2_SEMGREP,
                        PhaseName.L2_CODEQL,
                        PhaseName.L3_AGENT,
                        PhaseName.L3_ADJUDICATION,
                        PhaseName.REPORT_GENERATION,
                    ]
                    for phase in phase_order:
                        if phase not in checkpoint.phases:
                            resume_phase = phase
                            break
                        elif checkpoint.phases[phase].status in {"pending", "failed"}:
                            resume_phase = phase
                            break

            # Build reason
            reason_parts = []
            if skip_phases:
                reason_parts.append(f"Skip completed phases: {', '.join(skip_phases)}")
            if retry_phases:
                reason_parts.append(f"Retry phases: {', '.join(retry_phases)}")
            if resume_phase:
                reason_parts.append(f"Resume from phase: {resume_phase}")

            reason = "; ".join(reason_parts) if reason_parts else "Start from beginning"

            return ResumeStrategy(
                can_resume=True,
                resume_phase=resume_phase,
                skip_phases=skip_phases,
                retry_phases=retry_phases,
                reason=reason,
            )

        except Exception as e:
            logger.exception(f"Failed to determine resume strategy: {e}")
            return ResumeStrategy(
                can_resume=False,
                reason=f"Error determining strategy: {e}"
            )

    async def _save_checkpoint_to_file(
        self,
        checkpoint: CheckpointData,
    ) -> bool:
        """Save checkpoint to file as backup.

        Args:
            checkpoint: Checkpoint data to save

        Returns:
            True if save succeeded, False otherwise
        """
        try:
            checkpoint_dir = self._get_checkpoint_dir()
            file_path = checkpoint_dir / f"scan_{checkpoint.scan_id}_checkpoint.json"

            with open(file_path, "w") as f:
                f.write(checkpoint.model_dump_json(indent=2))

            logger.debug(f"Saved checkpoint to file: {file_path}")
            return True

        except Exception as e:
            logger.exception(f"Failed to save checkpoint to file: {e}")
            return False

    async def _delete_checkpoint_file(self, scan_id: int) -> bool:
        """Delete checkpoint file for a scan.

        Args:
            scan_id: ID of the scan

        Returns:
            True if deletion succeeded, False otherwise
        """
        try:
            checkpoint_dir = self._get_checkpoint_dir()
            file_path = checkpoint_dir / f"scan_{scan_id}_checkpoint.json"

            if file_path.exists():
                file_path.unlink()
                logger.debug(f"Deleted checkpoint file: {file_path}")

            return True

        except Exception as e:
            logger.exception(f"Failed to delete checkpoint file: {e}")
            return False


# ============================================================================
# Singleton Instance
# ============================================================================

_checkpoint_service: Optional[CheckpointService] = None


def get_checkpoint_service() -> CheckpointService:
    """Get or create checkpoint service instance.

    Returns:
        CheckpointService singleton instance
    """
    global _checkpoint_service
    if _checkpoint_service is None:
        _checkpoint_service = CheckpointService()
    return _checkpoint_service
