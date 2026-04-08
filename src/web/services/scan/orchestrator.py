"""Scan orchestrator.

The orchestrator manages the complete scan lifecycle, coordinating
different phases and handling error conditions.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
import asyncio
import logging


from .context import ScanContext, ScanConfig, ScanStatus, ScanType
from .events import ScanEventEmitter, EventType
from .phases import PreparationPhase, EngineScanPhase, VerificationPhase


logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Scan orchestrator.

    This class manages the complete scan lifecycle:

    1. Creates scan context with configuration
    2. Executes scan phases sequentially or in parallel
    3. Emits events for real-time updates
    4. Handles cancellation and errors
    5. Returns final scan results

    Example:
        orchestrator = ScanOrchestrator(
            scan_id=28,
            project_id=7,
            source_path=Path("/path/to/code"),
            config=ScanConfig(scan_type=ScanType.BASE),
        )

        result = await orchestrator.run()
    """

    def __init__(
        self,
        scan_id: int,
        project_id: int,
        source_path: Path | str,
        config: ScanConfig | dict[str, Any] | None = None,
        db_session_factory: Any = None,
    ):
        """Initialize scan orchestrator.

        Args:
            scan_id: Scan ID
            project_id: Project ID
            source_path: Path to source code
            config: Scan configuration
            db_session_factory: Database session factory for event handlers
        """
        self.scan_id = scan_id
        self.project_id = project_id
        self.source_path = Path(source_path) if isinstance(source_path, str) else source_path

        # Convert dict to ScanConfig if needed
        if isinstance(config, dict):
            self.config = ScanConfig(**config)
        elif config is None:
            self.config = ScanConfig()
        else:
            self.config = config

        # Create context and emitter
        self.context = ScanContext(
            scan_id=scan_id,
            project_id=project_id,
            source_path=self.source_path,
            config=self.config,
        )
        self.emitter = ScanEventEmitter(scan_id=scan_id)

        # Register database event handlers if session factory provided
        if db_session_factory:
            self._register_db_handlers(db_session_factory)

    def _register_db_handlers(self, db_session_factory: Any) -> None:
        """Register database event handlers.

        Args:
            db_session_factory: Database session factory
        """
        from .events.db_handler import DatabaseEventHandler

        db_handler = DatabaseEventHandler(db_session_factory)

        self.emitter.on(EventType.SCAN_START)(db_handler.on_scan_start)
        self.emitter.on(EventType.SCAN_COMPLETE)(db_handler.on_scan_complete)
        self.emitter.on(EventType.PHASE_START)(db_handler.on_phase_start)
        self.emitter.on(EventType.PHASE_COMPLETE)(db_handler.on_phase_complete)
        self.emitter.on(EventType.ENGINE_START)(db_handler.on_engine_start)
        self.emitter.on(EventType.ENGINE_COMPLETE)(db_handler.on_engine_complete)
        self.emitter.on(EventType.FINDING_NEW)(db_handler.on_finding_new)
        self.emitter.on(EventType.PROGRESS_UPDATE)(db_handler.on_progress_update)

    async def run(self) -> dict[str, Any]:
        """Run the scan.

        Executes all configured phases and returns the final result.

        Returns:
            Dictionary with scan results
        """
        start_time = datetime.now(timezone.utc)

        # Emit scan start event
        await self.emitter.emit_scan_start(
            source_path=str(self.source_path),
            scan_type=self.config.scan_type.value,
            config=self.config.to_dict(),
        )

        await self.context.set_status(ScanStatus.RUNNING)

        try:
            # Execute phases based on scan type
            if self.config.scan_type == ScanType.INCREMENTAL:
                result = await self._run_incremental_scan()
            else:
                result = await self._run_full_scan()

            # Calculate duration
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()

            # Emit scan complete event
            await self.emitter.emit_scan_complete(
                duration_seconds=duration,
                findings_total=self.context.statistics.findings_count,
                tokens_used=self.context.statistics.tokens_used,
            )

            await self.context.set_status(ScanStatus.COMPLETED)

            return {
                "success": True,
                "scan_id": self.scan_id,
                "findings": self.context.findings,
                "statistics": self.context.statistics.to_dict(),
                "duration_seconds": duration,
            }

        except asyncio.CancelledError:
            await self.emitter.emit(EventType.SCAN_CANCELLED)
            await self.context.set_status(ScanStatus.CANCELLED)
            return {
                "success": False,
                "scan_id": self.scan_id,
                "error": "Cancelled",
            }

        except Exception as e:
            logger.exception(f"Scan {self.scan_id} failed")

            await self.emitter.emit(EventType.SCAN_FAILED, {"error": str(e)})
            await self.context.set_status(ScanStatus.FAILED)

            return {
                "success": False,
                "scan_id": self.scan_id,
                "error": str(e),
            }

    async def _run_full_scan(self) -> dict[str, Any]:
        """Run full scan with all phases.

        Returns:
            Partial result with findings and statistics
        """
        # Phase 1: Preparation
        if self.context.is_cancelled():
            raise asyncio.CancelledError()

        await self.emitter.emit_phase_start("L1_preparation", "Tech Stack Detection")
        prep_phase = PreparationPhase()
        prep_result = await prep_phase.run(self.context)

        if not prep_result.success:
            raise Exception(f"Preparation phase failed: {prep_result.error}")

        await self.emitter.emit_phase_complete(
            "L1_preparation",
            duration_seconds=prep_result.duration_seconds,
            findings=0,
        )

        # Phase 2/3: Engine Scan
        if self.context.is_cancelled():
            raise asyncio.CancelledError()

        await self.emitter.emit_phase_start("L2_L3_engines", "Parallel Engine Scan")
        engine_phase = EngineScanPhase(engines=self.config.engines)
        engine_result = await engine_phase.run(self.context)

        if not engine_result.success:
            raise Exception(f"Engine phase failed: {engine_result.error}")

        await self.emitter.emit_phase_complete(
            "L2_L3_engines",
            duration_seconds=engine_result.duration_seconds,
            findings=len(engine_result.findings or []),
            tokens_used=engine_result.tokens_used,
        )

        # Phase 4: Verification (optional)
        if self.config.llm_verify and not self.context.is_cancelled():
            await self.emitter.emit_phase_start("L4_verification", "LLM Verification")
            verify_phase = VerificationPhase()
            verify_result = await verify_phase.run(self.context)

            if not verify_result.success:
                logger.warning(f"Verification phase failed: {verify_result.error}")
            else:
                await self.emitter.emit_phase_complete(
                    "L4_verification",
                    duration_seconds=verify_result.duration_seconds,
                    findings=len(verify_result.findings or []),
                    tokens_used=verify_result.tokens_used,
                )

        return {
            "findings": self.context.findings,
            "statistics": self.context.statistics.to_dict(),
        }

    async def _run_incremental_scan(self) -> dict[str, Any]:
        """Run incremental scan.

        Returns:
            Partial result with findings and statistics
        """
        # Import incremental scanner
        from src.layers.l3_analysis.incremental import IncrementalScanner, IncrementalScanConfig

        if not self.config.incremental_refs:
            raise ValueError("Incremental scan requires base_ref and head_ref")

        base_ref, head_ref = self.config.incremental_refs

        # Configure incremental scanner
        inc_config = IncrementalScanConfig(
            base_ref=base_ref,
            head_ref=head_ref,
            min_impact_score=0.15,
            max_dependency_depth=4,
        )

        # Create scan callback that uses our engines
        def create_scan_callback():
            async def scan_callback(files: list[str]) -> list[dict[str, Any]]:
                # Create a temporary context for this scan
                temp_context = ScanContext(
                    scan_id=self.scan_id,
                    project_id=self.project_id,
                    source_path=self.source_path,
                    config=self.config,
                )

                # Run engines on the changed files
                engine_phase = EngineScanPhase(engines=self.config.engines)
                await engine_phase.run(temp_context)

                return temp_context.findings

            return scan_callback

        scanner = IncrementalScanner(
            project_path=self.source_path,
            config=inc_config,
            scan_callback=create_scan_callback(),
        )

        # Run incremental scan
        result = await scanner.scan()

        # Update context with results
        for finding in result.findings or []:
            await self.context.add_finding(finding)

        return {
            "findings": self.context.findings,
            "statistics": {
                **self.context.statistics.to_dict(),
                "files_changed": result.files_changed,
                "files_added": result.files_added,
                "files_modified": result.files_modified,
            },
        }

    async def cancel(self) -> None:
        """Request scan cancellation."""
        await self.context.cancel()
