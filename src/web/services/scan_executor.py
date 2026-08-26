"""Scan executor service for managing scan lifecycle.

P10-07-10: This module provides the ScanExecutor service that orchestrates
the entire scan process, from creation through execution to completion.
It integrates with Celery tasks for background execution and provides
a high-level API for the web layer.

P11-03: Enhanced with pause/resume/cancel functionality.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.web.models.database import get_session_local
from src.web.models.scan import Scan, ScanStatus, ScanPhase, ScanEvent
from src.web.models.schemas import (
    ScanCreate,
    ScanProgressResponse,
    TokenInfo,
    FindingSummary,
    PhaseInfo,
    AgentConversationResponse,
    AgentConversationMessage,
    AdversarialStatus,
    CurrentFileResponse,
)
from src.web.repositories.scan import ScanRepository
from src.web.repositories.event import ScanEventRepository, ScanPhaseRepository
from src.web.repositories.finding import FindingRepository

# Import checkpoint and phase services for pause/resume
from src.web.services.checkpoint_service import CheckpointService, get_checkpoint_service

# Import Celery app for task control
from src.web.core.celery_app import get_celery_app


logger = logging.getLogger(__name__)


class ScanExecutor:
    """Service for managing scan lifecycle.

    This service provides:
    1. Scan creation and validation
    2. Celery task dispatch for background execution
    3. Progress tracking and status queries
    4. Pause/resume/cancel functionality
    5. Result retrieval and cleanup
    """

    def __init__(self):
        """Initialize scan executor."""
        self.scan_repo = ScanRepository()
        self.phase_repo = ScanPhaseRepository()
        self.event_repo = ScanEventRepository()
        self.finding_repo = FindingRepository()
        self.checkpoint_service = get_checkpoint_service()

    async def create_scan(
        self,
        scan_create: ScanCreate,
    ) -> Scan:
        """Create a new scan.

        Args:
            scan_create: Scan creation request

        Returns:
            Created scan instance
        """
        session_maker = get_session_local()
        async with session_maker() as db:
            # Serialize the pydantic ScanConfig to a JSON-safe dict before
            # storing: the SQLAlchemy JSON column cannot serialize pydantic
            # objects (TypeError), and ScanOrchestrator consumes a plain dict.
            config_data = (
                scan_create.config.model_dump(mode="json")
                if scan_create.config is not None
                else None
            )
            # Create scan record
            scan = Scan(
                name=scan_create.name,
                source_type=scan_create.source_type,
                source_path=scan_create.source_path,
                branch=scan_create.branch,
                scan_type=scan_create.scan_type,
                config=config_data,
                status=ScanStatus.PENDING,
                progress_percent=0,
                created_at=datetime.now(timezone.utc),
            )

            created_scan = await self.scan_repo.create(db, obj_in=scan)

            # Create initial phases
            await self._create_initial_phases(db, created_scan.id, scan_create.scan_type)

            await db.commit()
            await db.refresh(created_scan)

            return created_scan

    async def _create_initial_phases(
        self,
        db,
        scan_id: int,
        scan_type: str,
    ) -> None:
        """Create initial scan phase records.

        Args:
            db: Database session
            scan_id: ID of the scan
            scan_type: Type of scan (full/base/incremental)
        """
        # Phase 18/P5-A5: pre-insert all canonical ScanPhase values as pending.
        # Using ScanPhase values (not legacy PhaseName) keeps these rows aligned
        # with the ones the broadcaster writes at runtime, so scan_phases no
        # longer holds split PhaseName + ScanPhase rows for the same scan.
        from src.layers.pipeline.phases import SCAN_PHASE_ORDER

        for phase in SCAN_PHASE_ORDER:
            db.add(ScanPhase(
                scan_id=scan_id,
                phase_name=phase.value,
                status="pending",
                progress_percent=0,
            ))

        await db.flush()

    async def start_scan(self, scan_id: int) -> Dict[str, Any]:
        """Start a scan by dispatching to Celery.

        Args:
            scan_id: ID of the scan to start

        Returns:
            Dictionary with task ID and status

        Raises:
            ValueError: If scan not found or already running
        """
        from src.web.tasks.scan_tasks import execute_scan_task

        session_maker = get_session_local()
        async with session_maker() as db:
            scan = await self.scan_repo.get(db, id=scan_id)
            if scan is None:
                raise ValueError(f"Scan {scan_id} not found")

            if scan.status != ScanStatus.PENDING:
                raise ValueError(
                    f"Scan {scan_id} is not in pending status (current: {scan.status})"
                )

        # Dispatch to Celery with explicit routing
        task = execute_scan_task.apply_async(
            args=[scan_id],
            queue="scan",
            routing_key="scan"
        )

        logger.info(f"Started scan {scan_id}, Celery task ID: {task.id}")

        # Save task_id to database
        async with session_maker() as db:
            await self.scan_repo.update_task_id(db, scan_id=scan_id, task_id=task.id)
            await db.commit()

        return {
            "scan_id": scan_id,
            "task_id": task.id,
            "status": "dispatched",
        }

    async def get_scan_status(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """Get current scan status.

        Args:
            scan_id: ID of the scan

        Returns:
            Dictionary with scan status or None if not found
        """
        session_maker = get_session_local()
        async with session_maker() as db:
            scan = await self.scan_repo.get(db, id=scan_id)
            if scan is None:
                return None

            return {
                "scan_id": scan.id,
                "status": scan.status,
                "progress_percent": scan.progress_percent,
                "current_phase": scan.current_phase,
                "current_step": scan.current_step,
                "findings_count": scan.findings_count,
                "tokens_used": scan.tokens_used,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "error_message": scan.error_message,
            }

    async def get_scan_progress(self, scan_id: int) -> Optional[ScanProgressResponse]:
        """Get detailed scan progress.

        Args:
            scan_id: ID of the scan

        Returns:
            ScanProgressResponse with detailed progress or None
        """
        session_maker = get_session_local()
        async with session_maker() as db:
            scan = await self.scan_repo.get_with_phases(db, id=scan_id)
            if scan is None:
                return None

            # Get phases info
            phases = [
                PhaseInfo(
                    name=p.phase_name,
                    status=p.status,
                    progress_percent=p.progress_percent,
                    duration_seconds=p.duration_seconds,
                    findings=p.findings_found,
                    tokens_used=p.tokens_used,
                )
                for p in scan.phases
            ]

            # Build engine status
            completed_engines = [p.phase_name for p in scan.phases if p.status == "completed"]
            running_engines = [p.phase_name for p in scan.phases if p.status == "running"]
            pending_engines = [p.phase_name for p in scan.phases if p.status == "pending"]

            return ScanProgressResponse(
                scan_id=scan.id,
                status=scan.status,
                progress_percent=scan.progress_percent,
                current_phase=scan.current_phase,
                current_step=scan.current_step,
                current_engine=scan.current_engine,
                total_files=scan.total_files,
                indexed_files=scan.indexed_files,
                analyzed_files=scan.analyzed_files,
                files_with_findings=scan.files_with_findings,
                engines={
                    "completed": completed_engines,
                    "running": running_engines[0] if running_engines else None,
                    "pending": pending_engines,
                },
                tokens=TokenInfo.calculate(
                    scan.tokens_used, scan.tokens_budget
                ),
                findings=FindingSummary(
                    total=scan.findings_count,
                    verified=scan.verified_count,
                    false_positive=scan.false_positive_count,
                    by_severity={
                        "critical": scan.critical_count,
                        "high": scan.high_count,
                        "medium": scan.medium_count,
                        "low": scan.low_count,
                        "info": scan.info_count,
                    },
                ),
                phases=phases,
                started_at=scan.started_at,
                estimated_completion=scan.estimated_completion,
            )

    async def get_agent_conversation(
        self,
        scan_id: int,
    ) -> Optional[AgentConversationResponse]:
        """Get agent conversation for a scan.

        Args:
            scan_id: ID of the scan

        Returns:
            AgentConversationResponse with conversation or None
        """
        session_maker = get_session_local()
        async with session_maker() as db:
            scan = await self.scan_repo.get(db, id=scan_id)
            if scan is None:
                return None

            # Get agent events
            events = await self.event_repo.get_agent_conversation(db, scan_id=scan_id, limit=100)

            conversation = []
            for event in events:
                message = AgentConversationMessage(
                    turn=event.agent_turn,
                    role=event.agent_role or "unknown",
                    message=event.agent_message or event.message or "",
                    reasoning=event.agent_reasoning,
                    action=event.details.get("action") if event.details else None,
                    tool_name=event.details.get("tool_name") if event.details else None,
                    tool_input=event.details.get("tool_input") if event.details else None,
                    tokens=event.tokens_used,
                )
                conversation.append(message)

            # Get adversarial status
            adv_status = self._extract_adversarial_status(events)

            # Get current file info
            current_file = self._extract_current_file_info(events)

            return AgentConversationResponse(
                scan_id=scan_id,
                phase=scan.current_phase,
                current_file=current_file,
                conversation=conversation,
                adversarial_status=adv_status,
            )

    def _extract_adversarial_status(self, events: List[ScanEvent]) -> AdversarialStatus:
        """Extract adversarial verification status from events.

        Args:
            events: List of scan events

        Returns:
            AdversarialStatus with current state
        """
        # Look for recent adversarial events
        adv_events = [e for e in events if "adversarial" in e.event_type]

        if not adv_events:
            return AdversarialStatus()

        latest = adv_events[-1]

        if latest.event_type == "adversarial_complete":
            return AdversarialStatus(active=False)

        if latest.details:
            return AdversarialStatus(
                active=True,
                round=latest.details.get("round", 0),
                max_rounds=latest.details.get("max_rounds", 5),
                current_findings=latest.details.get("current_findings", 0),
                verifying_finding_id=latest.details.get("finding_id"),
            )

        return AdversarialStatus(active=True)

    def _extract_current_file_info(self, events: List[ScanEvent]) -> Optional[Dict[str, Any]]:
        """Extract current file being processed from events.

        Args:
            events: List of scan events

        Returns:
            Dictionary with file info or None
        """
        # Look for recent file_start event
        for event in reversed(events):
            if event.event_type == "file_start" and event.file_path:
                return {
                    "path": event.file_path,
                    "index": event.file_index,
                    "total": event.file_total,
                    "findings_in_file": 0,  # Will be updated by file_complete
                }

        return None

    async def get_current_file(self, scan_id: int) -> Optional[CurrentFileResponse]:
        """Get current file being scanned.

        Args:
            scan_id: ID of the scan

        Returns:
            CurrentFileResponse with file details or None
        """
        session_maker = get_session_local()
        async with session_maker() as db:
            scan = await self.scan_repo.get(db, id=scan_id)
            if scan is None:
                return None

            # Get recent events
            events = await self.event_repo.get_recent_by_scan(db, scan_id=scan_id, limit=20)

            current_file = self._extract_current_file_info(events)

            # Get file preview (would need to read from disk)
            file_preview = None
            if current_file:
                # TODO: Implement file reading for preview
                pass

            # Get agent actions on file
            agent_actions = []
            for event in events:
                if event.event_type in ["agent_action", "agent_thinking"]:
                    agent_actions.append({
                        "timestamp": event.created_at.isoformat(),
                        "action": event.event_type,
                        "result": event.message,
                    })

            return CurrentFileResponse(
                scan_id=scan_id,
                current_file=current_file,
                file_preview=file_preview,
                agent_actions_on_file=agent_actions,
            )

    async def pause_scan(self, scan_id: int) -> Dict[str, Any]:
        """Pause a running scan.

        Args:
            scan_id: ID of the scan to pause

        Returns:
            Dictionary with pause result

        Raises:
            ValueError: If scan not found or cannot be paused
        """
        session_maker = get_session_local()
        async with session_maker() as db:
            scan = await self.scan_repo.get(db, id=scan_id)
            if scan is None:
                raise ValueError(f"Scan {scan_id} not found")

            if scan.status != ScanStatus.RUNNING:
                raise ValueError(
                    f"Scan {scan_id} is not running (current: {scan.status})"
                )

            # Get current phase
            current_phase_name = scan.current_phase
            if current_phase_name:
                # Audit B1: save_checkpoint REPLACES the whole checkpoint, so a
                # hand-rolled minimal payload used to wipe the orchestrator's
                # resume_data (scan_results / completed_engines) — resuming then
                # re-ran every engine and lost findings. Merge on top of the
                # checkpoint already carried by the scan row instead.
                prev_checkpoint = (
                    scan.checkpoint_data
                    if isinstance(scan.checkpoint_data, dict)
                    else {}
                )
                prev_resume = prev_checkpoint.get("resume_data") or {}
                checkpoint_data = {
                    "global_state": {
                        "scan_type": scan.scan_type,
                        "config": scan.config,
                    },
                    "resume_data": {
                        **prev_resume,
                        "total_files": scan.total_files,
                        "analyzed_files": scan.analyzed_files,
                        "findings_count": scan.findings_count,
                        "tokens_used": scan.tokens_used,
                    },
                }

                saved = await self.checkpoint_service.save_checkpoint(
                    scan_id=scan_id,
                    phase=current_phase_name,
                    data=checkpoint_data,
                )

                if not saved:
                    logger.warning(f"Failed to save checkpoint for scan {scan_id}")
            else:
                logger.warning(f"Scan {scan_id} has no current phase, cannot save checkpoint")

            # Revoke the Celery task if a task_id exists. Phase 18/P5-A6: pause
            # must actually stop the worker, not just flip the DB status —
            # otherwise the paused scan and the still-running task race and
            # produce duplicate findings. Mirrors cancel_scan's revocation.
            task_revoked = False
            if scan.task_id:
                try:
                    celery_app = get_celery_app()
                    celery_app.control.revoke(
                        scan.task_id, terminate=True, signal='SIGTERM'
                    )
                    task_revoked = True
                    logger.info(f"Revoked Celery task {scan.task_id} for paused scan {scan_id}")
                except Exception as e:
                    logger.error(f"Failed to revoke Celery task {scan.task_id}: {e}")
                    # Continue to update status even if revocation fails

            # Update scan status to paused
            await self.scan_repo.update_status(
                db,
                scan_id=scan_id,
                status=ScanStatus.PAUSED,
            )
            await db.commit()

            logger.info(f"Paused scan {scan_id}")
            return {
                "scan_id": scan_id,
                "status": ScanStatus.PAUSED,
                "checkpoint_saved": current_phase_name is not None,
                "paused_at": datetime.now(timezone.utc).isoformat(),
                "current_phase": current_phase_name,
                "can_resume": True,
                "task_revoked": task_revoked,
            }

    async def resume_scan(self, scan_id: int) -> Dict[str, Any]:
        """Resume a paused scan.

        Args:
            scan_id: ID of the scan to resume

        Returns:
            Dictionary with resume result

        Raises:
            ValueError: If scan not found or cannot be resumed
        """
        session_maker = get_session_local()
        async with session_maker() as db:
            scan = await self.scan_repo.get(db, id=scan_id)
            if scan is None:
                raise ValueError(f"Scan {scan_id} not found")

            if scan.status != ScanStatus.PAUSED:
                raise ValueError(
                    f"Scan {scan_id} is not paused (current: {scan.status})"
                )

            # Load checkpoint to determine resume strategy
            checkpoint = await self.checkpoint_service.load_checkpoint(scan_id)

            if checkpoint is None:
                raise ValueError(f"No checkpoint found for scan {scan_id}")

            # Verify checkpoint
            valid = await self.checkpoint_service.verify_checkpoint(checkpoint)
            if not valid:
                raise ValueError(f"Checkpoint for scan {scan_id} is invalid")

            # Get resume strategy
            strategy = await self.checkpoint_service.get_resume_strategy(checkpoint)

            if not strategy.can_resume:
                raise ValueError(f"Cannot resume scan {scan_id}: {strategy.reason}")

            # Update scan status back to pending for restart
            await self.scan_repo.update_status(
                db,
                scan_id=scan_id,
                status=ScanStatus.PENDING,
            )
            await db.commit()

            # Start new Celery task with resume data
            from src.web.tasks.scan_tasks import execute_scan_task

            task = execute_scan_task.apply_async(
                args=[scan_id],
                kwargs={"resume_from": strategy.resume_phase}
            )

            logger.info(
                f"Resumed scan {scan_id} from phase {strategy.resume_phase}, "
                f"task_id: {task.id}"
            )
            return {
                "scan_id": scan_id,
                "status": ScanStatus.PENDING,
                "resumed_from_phase": strategy.resume_phase,
                "resumed_at": datetime.now(timezone.utc).isoformat(),
                "task_id": task.id,
                "skip_phases": strategy.skip_phases,
            }

    async def cancel_scan(self, scan_id: int) -> bool:
        """Cancel a running scan.

        Args:
            scan_id: ID of the scan to cancel

        Returns:
            True if cancelled successfully
        """
        session_maker = get_session_local()
        async with session_maker() as db:
            scan = await self.scan_repo.get(db, id=scan_id)
            if scan is None:
                return False

            if scan.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
                return False

            # Revoke Celery task if task_id exists
            if scan.task_id:
                try:
                    celery_app = get_celery_app()
                    # Use Celery control to revoke the task
                    # terminate=True will kill the task immediately
                    celery_app.control.revoke(scan.task_id, terminate=True, signal='SIGTERM')
                    logger.info(f"Revoked Celery task {scan.task_id} for scan {scan_id}")
                except Exception as e:
                    logger.error(f"Failed to revoke Celery task {scan.task_id}: {e}")
                    # Continue to update status even if revocation fails

            # Update scan status
            await self.scan_repo.update_status(
                db,
                scan_id=scan_id,
                status=ScanStatus.CANCELLED,
            )
            await db.commit()

            logger.info(f"Cancelled scan {scan_id}")
            return True

    async def retry_scan(self, scan_id: int) -> Dict[str, Any]:
        """Retry a failed scan.

        Args:
            scan_id: ID of the scan to retry

        Returns:
            Dictionary with new scan ID and task ID

        Raises:
            ValueError: If original scan not found or not failed
        """
        session_maker = get_session_local()
        async with session_maker() as db:
            scan = await self.scan_repo.get(db, id=scan_id)
            if scan is None:
                raise ValueError(f"Scan {scan_id} not found")

            if scan.status != ScanStatus.FAILED:
                raise ValueError(
                    f"Scan {scan_id} is not in failed status (current: {scan.status})"
                )

            # Create new scan based on old one
            from src.web.models.schemas import ScanCreate

            scan_create = ScanCreate(
                name=scan.name,
                source_type=scan.source_type,
                source_path=scan.source_path,
                branch=scan.branch,
                scan_type=scan.scan_type,
                config=scan.config,
            )

            new_scan = await self.create_scan(scan_create)

            # Start the new scan
            result = await self.start_scan(new_scan.id)

            return {
                "original_scan_id": scan_id,
                "new_scan_id": new_scan.id,
                "task_id": result["task_id"],
            }


# Singleton instance
_scan_executor: Optional[ScanExecutor] = None


def get_scan_executor() -> ScanExecutor:
    """Get or create scan executor instance."""
    global _scan_executor
    if _scan_executor is None:
        _scan_executor = ScanExecutor()
    return _scan_executor
