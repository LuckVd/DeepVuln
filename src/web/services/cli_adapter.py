"""CLI adapter for running deepvuln scan and parsing JSONL output.

P10-07: This module provides the CLIAdapter class that handles running
the deepvuln CLI as a subprocess and parsing its JSONL output for
real-time progress tracking.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.web.models.schemas import ScanType

logger = logging.getLogger(__name__)


class CLIAdapter:
    """Adapter for running deepvuln CLI and parsing JSONL output.

    This adapter:
    1. Constructs the deepvuln command based on scan configuration
    2. Runs the command as a subprocess
    3. Parses JSONL output line by line
    4. Updates the database with progress and results
    """

    def __init__(
        self,
        scan_id: int,
        project_id: int,
        scan_config: Dict[str, Any],
        resume_from: Optional[Dict[str, Any]] = None,
    ):
        """Initialize CLI adapter.

        Args:
            scan_id: ID of the scan in the database
            project_id: ID of the project being scanned
            scan_config: Scan configuration dictionary
            resume_from: Optional resume data containing phase and checkpoint
        """
        self.scan_id = scan_id
        self.project_id = project_id
        self.scan_config = scan_config
        self.resume_from = resume_from

        # Internal state
        self._process: Optional[asyncio.subprocess.Process] = None
        self._output_lines: List[str] = []
        self._events_emitted: int = 0

    def _build_command(self, source_path: Path) -> List[str]:
        """Build deepvuln command based on scan configuration.

        Args:
            source_path: Path to source code

        Returns:
            List of command arguments
        """
        cmd = ["deepvuln", "scan", "-p", str(source_path)]

        # Resume support
        if self.resume_from:
            resume_phase = self.resume_from.get("resume_phase")
            if resume_phase:
                cmd.extend(["--resume-phase", resume_phase])
                logger.info(f"Resuming scan from phase: {resume_phase}")

        # Scan type
        scan_type = self.scan_config.get("scan_type", "full")
        if scan_type == "full":
            cmd.append("--full")
        elif scan_type == "base":
            cmd.append("--base")
        elif scan_type == ScanType.INCREMENTAL:
            cmd.append("--incremental")

        # Engines
        engines = self.scan_config.get("engines")
        if engines:
            for engine in engines:
                cmd.extend(["--engines", engine])

        # LLM verification
        if self.scan_config.get("llm_verify"):
            cmd.append("--llm-verify")

        # Adversarial verification
        if self.scan_config.get("adversarial"):
            cmd.append("--adversarial")

        # Model
        model = self.scan_config.get("model")
        if model:
            cmd.extend(["--model", model])

        # Incremental scan options
        if scan_type == ScanType.INCREMENTAL:
            base_ref = self.scan_config.get("base_ref", "HEAD~1")
            head_ref = self.scan_config.get("head_ref", "HEAD")
            cmd.extend(["--base-ref", base_ref])
            cmd.extend(["--head-ref", head_ref])

        # JSONL output format
        cmd.extend(["--output-format", "jsonl"])

        # Include low severity
        if self.scan_config.get("include_low_severity"):
            cmd.append("--include-low")

        # Agent max files
        agent_max_files = self.scan_config.get("agent_max_files")
        if agent_max_files:
            cmd.extend(["--agent-max-files", str(agent_max_files)])

        return cmd

    async def _parse_output_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single line of JSONL output.

        Args:
            line: JSONL line to parse

        Returns:
            Parsed event dictionary, or None if not valid JSON
        """
        try:
            event = json.loads(line.strip())
            # Add scan_id and timestamp
            event["scan_id"] = self.scan_id
            event["created_at"] = datetime.now(timezone.utc).isoformat()
            return event
        except json.JSONDecodeError:
            return None

    async def _process_output_line(self, line: str) -> None:
        """Process a single line of CLI output.

        This parses the JSONL event and updates the database.

        Args:
            line: Output line from CLI
        """
        event = await self._parse_output_line(line)
        if event is None:
            return

        self._events_emitted += 1

        # Update database based on event type
        from src.web.models.database import get_session_local
        from src.web.repositories.event import ScanEventRepository, ScanPhaseRepository

        event_repo = ScanEventRepository()
        phase_repo = ScanPhaseRepository()

        async with get_session_local() as db:
            event_type = event.get("type", "")

            # Handle different event types
            if event_type == "phase_start":
                # Create phase record
                from src.web.models.scan import ScanPhase

                phase = ScanPhase(
                    scan_id=self.scan_id,
                    phase_name=event.get("phase", ""),
                    status="running",
                    started_at=datetime.now(timezone.utc),
                )
                await phase_repo.create(db, obj_in=phase)

            elif event_type == "phase_complete":
                # Update phase record
                await self._update_phase_complete(
                    db, phase_repo, event
                )

            elif event_type == "engine_start":
                # Could track engine status
                pass

            elif event_type == "engine_complete":
                # Update engine statistics
                pass

            elif event_type == "file_start":
                # Update progress
                await self._update_file_progress(db, event)

            elif event_type == "file_complete":
                # Update file completion stats
                await self._update_file_complete(db, event)

            elif event_type == "finding_new":
                # Store finding
                await self._store_finding(db, event)

            elif event_type == "finding_verified":
                # Update finding status
                await self._update_finding_verified(db, event)

            elif event_type == "scan_complete":
                # Update final statistics
                await self._update_scan_complete(db, event)

            elif event_type == "scan_failed":
                # Handle scan failure
                await self._handle_scan_failure(db, event)

            # Store all events for real-time WebSocket streaming
            await event_repo.create(db, obj_in=event)

    async def _update_phase_complete(
        self,
        db,
        phase_repo: "ScanPhaseRepository",
        event: Dict[str, Any],
    ) -> None:
        """Update phase record on completion.

        Args:
            db: Database session
            phase_repo: Phase repository
            event: Phase complete event
        """
        from src.web.models.scan import ScanPhase
        from sqlalchemy import select, update

        phase_name = event.get("phase", "")

        # Find the phase and update it
        result = await db.execute(
            select(ScanPhase)
            .where(ScanPhase.scan_id == self.scan_id)
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
                    completed_at=datetime.now(timezone.utc),
                    duration_seconds=event.get("duration_seconds", 0),
                    findings_found=event.get("findings", 0),
                    tokens_used=event.get("tokens_used", 0),
                )
            )
            await db.commit()

    async def _update_file_progress(
        self,
        db,
        event: Dict[str, Any],
    ) -> None:
        """Update scan progress based on file processing.

        Args:
            db: Database session
            event: File start event
        """
        from src.web.models.scan import Scan
        from sqlalchemy import update

        file_index = event.get("index", 0)
        total_files = event.get("total", 0)

        if total_files > 0:
            progress_percent = int((file_index / total_files) * 100)

            await db.execute(
                update(Scan)
                .where(Scan.id == self.scan_id)
                .values(
                    progress_percent=progress_percent,
                    current_step=f"Processing file {file_index}/{total_files}",
                )
            )
            await db.commit()

    async def _update_file_complete(
        self,
        db,
        event: Dict[str, Any],
    ) -> None:
        """Update statistics when file processing completes.

        Args:
            db: Database session
            event: File complete event
        """
        # Update analyzed_files count
        # This is a simplified implementation
        pass

    async def _store_finding(
        self,
        db,
        event: Dict[str, Any],
    ) -> None:
        """Store a new finding in the database.

        Args:
            db: Database session
            event: Finding new event
        """
        from src.web.models.finding import Finding

        finding = Finding(
            scan_id=self.scan_id,
            vuln_type=event.get("vuln_type", ""),
            severity=event.get("severity", ""),
            confidence=event.get("confidence", 0.0),
            file_path=event.get("file", ""),
            line_start=event.get("line", 0),
            title=event.get("title", ""),
            engine=event.get("engine", ""),
            status="pending",
        )
        db.add(finding)
        await db.commit()

    async def _update_finding_verified(
        self,
        db,
        event: Dict[str, Any],
    ) -> None:
        """Update finding verification status.

        Args:
            db: Database session
            event: Finding verified event
        """
        # TODO: Implement finding verification update
        pass

    async def _update_scan_complete(
        self,
        db,
        event: Dict[str, Any],
    ) -> None:
        """Update scan on completion.

        Args:
            db: Database session
            event: Scan complete event
        """
        from src.web.models.scan import Scan
        from sqlalchemy import update

        await db.execute(
            update(Scan)
            .where(Scan.id == self.scan_id)
            .values(
                status="completed",
                completed_at=datetime.now(timezone.utc),
                progress_percent=100,
                findings_count=event.get("findings_total", 0),
                tokens_used=event.get("tokens_used", 0),
            )
        )
        await db.commit()

    async def _handle_scan_failure(
        self,
        db,
        event: Dict[str, Any],
    ) -> None:
        """Handle scan failure.

        Args:
            db: Database session
            event: Scan failed event
        """
        from src.web.models.scan import Scan
        from sqlalchemy import update

        await db.execute(
            update(Scan)
            .where(Scan.id == self.scan_id)
            .values(
                status="failed",
                error_message=event.get("error_message", "Unknown error"),
            )
        )
        await db.commit()

    async def run_scan(self) -> Dict[str, Any]:
        """Run the CLI scan synchronously.

        This method is used by the Celery task to execute the scan.

        Returns:
            Dictionary containing:
                - success: bool - True if scan completed successfully
                - findings_count: int - Number of findings found
                - duration_seconds: float - Scan duration
                - error: str | None - Error message if failed
        """
        from src.web.repositories.project import ProjectRepository
        from src.web.repositories.scan import ScanRepository
        from src.web.services.incremental_scan import get_incremental_scan_service
        from src.web.models.database import get_session_local

        # Get project details
        project_repo = ProjectRepository()
        scan_repo = ScanRepository()

        async with get_session_local() as db:
            project = await project_repo.get(db, id=self.project_id)
            if project is None:
                raise ValueError(f"Project {self.project_id} not found")

            source_path = Path(project.source_path)

            # For incremental scans, analyze changes first
            scan_type = self.scan_config.get("scan_type", "full")
            if scan_type == "incremental":
                incremental_service = get_incremental_scan_service(
                    self.scan_id, self.project_id
                )
                base_ref = self.scan_config.get("base_ref", "HEAD~1")
                head_ref = self.scan_config.get("head_ref", "HEAD")

                try:
                    context = await incremental_service.analyze_incremental_changes(
                        source_path, base_ref, head_ref
                    )
                    # Update scan with incremental statistics
                    await incremental_service.update_scan_with_incremental_stats(
                        db, context
                    )
                    logger.info(
                        f"Incremental scan analysis complete: "
                        f"{context.added_files} added, {context.modified_files} modified"
                    )
                except Exception as e:
                    logger.warning(f"Incremental analysis failed: {e}, continuing with full scan")

        # Build command
        cmd = self._build_command(source_path)

        logger.info(f"Running scan {self.scan_id} with command: {' '.join(cmd)}")

        # Track start time
        start_time = datetime.now(timezone.utc)

        try:
            # Run subprocess
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(source_path.parent),
            )

            self._process = process

            # Process output line by line
            while True:
                line = await process.stdout.readline()
                if not line:
                    break

                line_str = line.decode("utf-8").strip()
                if line_str:
                    self._output_lines.append(line_str)
                    await self._process_output_line(line_str)

            # Wait for process to complete
            return_code = await process.wait()

            if return_code != 0:
                # Read stderr for error message
                stderr_output = await process.stderr.read()
                stderr_str = stderr_output.decode("utf-8")

                return {
                    "success": False,
                    "error": f"CLI exited with code {return_code}: {stderr_str}",
                    "findings_count": 0,
                    "duration_seconds": (datetime.now(timezone.utc) - start_time).total_seconds(),
                }

            # Parse final output
            findings_count = 0
            for line in self._output_lines:
                event = await self._parse_output_line(line)
                if event and event.get("type") == "scan_complete":
                    findings_count = event.get("findings_total", 0)
                    break

            return {
                "success": True,
                "findings_count": findings_count,
                "duration_seconds": (datetime.now(timezone.utc) - start_time).total_seconds(),
            }

        except asyncio.CancelledError:
            # Task was cancelled
            if self._process:
                self._process.kill()

            return {
                "success": False,
                "error": "Scan was cancelled",
                "findings_count": 0,
                "duration_seconds": (datetime.now(timezone.utc) - start_time).total_seconds(),
            }

        except Exception as e:
            logger.exception(f"Scan {self.scan_id} failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "findings_count": 0,
                "duration_seconds": (datetime.now(timezone.utc) - start_time).total_seconds(),
            }
        finally:
            if self._process:
                self._process.kill()
