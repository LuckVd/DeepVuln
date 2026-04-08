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
        import sys
        # Use the same Python interpreter that's running the web service
        python_executable = sys.executable
        cmd = [python_executable, "-m", "src.cli.main", "scan", "-p", str(source_path)]

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
            event["created_at"] = datetime.utcnow().isoformat()
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

        session_maker = get_session_local()
        async with session_maker() as db:
            event_type = event.get("type", "")

            # Handle different event types
            if event_type == "phase_start":
                # Create phase record
                from src.web.models.scan import ScanPhase

                phase = ScanPhase(
                    scan_id=self.scan_id,
                    phase_name=event.get("phase", ""),
                    status="running",
                    started_at=datetime.utcnow(),
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
            # Map CLI event fields to database model fields
            event_data = {
                "scan_id": self.scan_id,
                "event_type": event.get("type", "info"),
                "event_level": event.get("level", "info"),
                "message": event.get("message", ""),
                "details": event.get("data"),
                "engine_name": event.get("engine"),
                "agent_turn": event.get("turn", 0),
                "agent_role": event.get("role"),
                "agent_message": event.get("agent_message"),
                "agent_reasoning": event.get("reasoning"),
                "file_path": event.get("file"),
                "file_index": event.get("index", 0),
                "file_total": event.get("total", 0),
                "tokens_used": event.get("tokens", 0),
                "tokens_input": event.get("tokens_in", 0),
                "tokens_output": event.get("tokens_out", 0),
                "sequence": event.get("seq", 0),
            }
            await event_repo.create(db, obj_in=event_data)

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
                    completed_at=datetime.utcnow(),
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
        from src.web.models.scan import Scan
        from sqlalchemy import update

        # Get file index and total from event
        file_index = event.get("index", 0)
        total_files = event.get("total", 0)

        # Update scan with progress and file count
        update_values = {
            "analyzed_files": file_index,
        }

        # Also set total_files if we have it
        if total_files > 0:
            update_values["total_files"] = total_files
            update_values["indexed_files"] = file_index
            progress_percent = int((file_index / total_files) * 100)
            update_values["progress_percent"] = progress_percent

        await db.execute(
            update(Scan)
            .where(Scan.id == self.scan_id)
            .values(**update_values)
        )
        await db.commit()

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

        # Clean up file path - remove temporary directory prefix
        file_path = event.get("file", "")
        if file_path and "/deepvuln_scan_" in file_path:
            # Extract relative path after temporary directory
            parts = file_path.split("/java-simple-vuln/")
            if len(parts) > 1:
                file_path = parts[1]
            else:
                # Fallback: get last 2 parts
                parts = file_path.split("/")
                if len(parts) >= 2:
                    file_path = "/".join(parts[-2:])

        finding = Finding(
            scan_id=self.scan_id,
            vuln_type=event.get("vuln_type", ""),
            severity=event.get("severity", ""),
            confidence=event.get("confidence", 0.0),
            file_path=file_path,
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
        from src.web.models.finding import Finding
        from sqlalchemy import update, select, func

        # Calculate statistics from findings table
        findings_result = await db.execute(
            select(
                func.count().label("total"),
                func.sum(func.case((Finding.severity == "critical", 1), else_=0)).label("critical"),
                func.sum(func.case((Finding.severity == "high", 1), else_=0)).label("high"),
                func.sum(func.case((Finding.severity == "medium", 1), else_=0)).label("medium"),
                func.sum(func.case((Finding.severity == "low", 1), else_=0)).label("low"),
                func.sum(func.case((Finding.severity == "info", 1), else_=0)).label("info"),
            ).where(Finding.scan_id == self.scan_id)
        )
        stats = findings_result.one()

        # Get file statistics from phases
        from src.web.models.scan import ScanPhase
        phases_result = await db.execute(
            select(
                func.sum(ScanPhase.files_processed).label("files_processed"),
                func.sum(ScanPhase.tokens_used).label("tokens_used"),
            ).where(ScanPhase.scan_id == self.scan_id)
        )
        phase_stats = phases_result.one()

        # Update scan with complete statistics
        update_values = {
            "status": "completed",
            "completed_at": datetime.utcnow(),
            "progress_percent": 100,
            "findings_count": stats.total or 0,
            "critical_count": int(stats.critical or 0),
            "high_count": int(stats.high or 0),
            "medium_count": int(stats.medium or 0),
            "low_count": int(stats.low or 0),
            "info_count": int(stats.info or 0),
            "analyzed_files": int(phase_stats.files_processed or 0),
            "tokens_used": event.get("tokens_used", 0) or int(phase_stats.tokens_used or 0),
        }

        await db.execute(
            update(Scan)
            .where(Scan.id == self.scan_id)
            .values(**update_values)
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

        session_maker = get_session_local()
        async with session_maker() as db:
            project = await project_repo.get(db, id=self.project_id)
            if project is None:
                raise ValueError(f"Project {self.project_id} not found")

            source_path = Path(project.source_path)

            # Handle ZIP files - extract to a temporary directory
            if source_path.suffix == ".zip":
                import tempfile
                import shutil

                # Create temp directory for extraction
                temp_dir = Path(tempfile.mkdtemp(prefix="deepvuln_scan_"))
                try:
                    logger.info(f"Extracting ZIP file: {source_path} -> {temp_dir}")
                    shutil.unpack_archive(source_path, temp_dir)

                    # Find the extracted directory (usually contains the actual files)
                    extracted_items = list(temp_dir.iterdir())
                    if extracted_items and len(extracted_items) == 1 and extracted_items[0].is_dir():
                        source_path = extracted_items[0]
                        logger.info(f"Using extracted directory: {source_path}")
                    else:
                        # If extraction resulted in multiple files/directories, use the temp dir itself
                        source_path = temp_dir
                        logger.info(f"Using temp extraction directory: {source_path}")

                    # Store temp_dir for cleanup
                    self._temp_extraction_dir = temp_dir
                except Exception as e:
                    # Clean up temp dir if extraction failed
                    import os
                    if os.path.exists(temp_dir):
                        shutil.rmtree(temp_dir)
                    raise ValueError(f"Failed to extract ZIP file: {e}")

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
        start_time = datetime.utcnow()

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
                    "duration_seconds": (datetime.utcnow() - start_time).total_seconds(),
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
                "duration_seconds": (datetime.utcnow() - start_time).total_seconds(),
            }

        except asyncio.CancelledError:
            # Task was cancelled
            if self._process:
                self._process.kill()

            return {
                "success": False,
                "error": "Scan was cancelled",
                "findings_count": 0,
                "duration_seconds": (datetime.utcnow() - start_time).total_seconds(),
            }

        except Exception as e:
            logger.exception(f"Scan {self.scan_id} failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "findings_count": 0,
                "duration_seconds": (datetime.utcnow() - start_time).total_seconds(),
            }
        finally:
            # Clean up process if still running
            if self._process:
                try:
                    if self._process.returncode is None:
                        self._process.kill()
                except ProcessLookupError:
                    # Process already terminated
                    pass
                except Exception as e:
                    logger.warning(f"Failed to kill process: {e}")
            # Clean up temporary extraction directory if created
            if hasattr(self, '_temp_extraction_dir') and self._temp_extraction_dir:
                import shutil
                import os
                try:
                    if os.path.exists(self._temp_extraction_dir):
                        shutil.rmtree(self._temp_extraction_dir)
                        logger.info(f"Cleaned up temp directory: {self._temp_extraction_dir}")
                except Exception as e:
                    logger.warning(f"Failed to clean up temp directory: {e}")
                finally:
                    self._temp_extraction_dir = None
