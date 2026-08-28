"""Scan orchestrator for direct engine invocation.

This module provides the ScanOrchestrator class that replaces CLIAdapter
and directly invokes analysis engines (Semgrep, CodeQL, Agent) in the
current Python process using asyncio for concurrency.

Reference: DeepAudit's in-process scanning approach
"""

import asyncio
import logging
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.layers.l3_analysis.engines.base import BaseEngine
from src.layers.l3_analysis.models import ScanResult, Finding
from src.layers.l1_intelligence.tech_stack_detector.detector import TechStackDetector
from src.layers.l3_analysis.llm.client import LLMClient
from src.layers.pipeline.context import ScanContext
from src.layers.pipeline.phases import PhaseSpec, ScanPhase
from src.layers.pipeline.scan_pipeline import ScanPipeline
from src.web.models.database import get_session_local
from src.web.services.scan_pipeline_adapters import (
    WebCheckpointSink,
    WebProgressSink,
)
from src.web.models.finding import Finding as FindingModel
from src.web.services.archive_utils import safe_unpack_archive
from src.web.services.progress_broadcaster import (
    ProgressCallback,
    ProgressBroadcaster,
)
from src.web.services.attack_surface_service import (
    AttackSurfaceService,
    AttackSurfaceDetectionConfig,
    DetectionMode,
)
from src.core.models.attack_surface import AttackSurfaceReport
from src.web.services.verification_service import (
    create_verification_service,
)
from src.web.services.adjudication_service import (
    create_adjudication_service,
)
from src.web.services.adversarial_service import (
    create_adversarial_service_from_db,
)
from src.web.services.incremental_scan import (
    IncrementalScanService,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Scan Orchestrator
# ============================================================================


class ScanOrchestrator:
    """
    Orchestrates the complete scan workflow by directly invoking engines.

    This replaces CLIAdapter with a pure Python implementation that:
    - Prepares source code (ZIP extraction, file filtering)
    - Detects tech stack
    - Selects appropriate engines
    - Executes engines concurrently using asyncio.gather()
    - Merges and saves results

    Reference design: DeepAudit's process_zip_task() and scan_repo_task()
    """

    def __init__(
        self,
        scan_id: int,
        source_path: str,
        scan_config: Dict[str, Any],
        progress_callback: Optional[ProgressCallback] = None,
        db_session_factory: Optional[Callable[[], AsyncSession]] = None,
        llm_client: Optional[LLMClient] = None,
        source_type: Optional[str] = None,
    ):
        """Initialize the scan orchestrator.

        Args:
            scan_id: ID of the scan in the database
            source_path: Path to the source code to scan
            scan_config: Scan configuration dictionary
            progress_callback: Optional progress callback for events
            db_session_factory: Factory function for creating DB sessions
            llm_client: Optional LLM client for LLM-based features
            source_type: Type of source ("local", "git", "zip")
        """
        self.scan_id = scan_id
        self.source_path = source_path
        self.source_type = source_type or "local"
        self.config = scan_config
        self.progress_callback = progress_callback or ProgressBroadcaster(
            scan_id, db_session_factory
        )
        self.db_session_factory = db_session_factory or get_session_local
        self.llm_client = llm_client

        # Runtime state
        self.temp_dir: Optional[Path] = None
        self.tech_stack: Optional[Dict[str, Any]] = None
        self.attack_surface_report_obj: Optional[AttackSurfaceReport] = None  # Original AttackSurfaceReport object
        self.attack_surface_report: Optional[Dict[str, Any]] = None  # Finding context dict
        self.scan_results: Dict[str, ScanResult] = {}
        # P7-C6: engines that finished within engine_execution, for per-engine
        # incremental checkpoint / resume-skip. Reset on fresh scan; restored
        # (intersected with restored results) on resume.
        self._completed_engines: set[str] = set()
        # P3: agent is_suspicious entries pulled out of the reportable set,
        # kept here (as dicts) for manual review instead of being persisted.
        self._suspicious_review_queue: list[dict] = []
        # Phase 20 P-A2: gate-not-applicable findings pulled out of the
        # reportable set (same review-queue pattern as P3 suspicious).
        self._gated_review_queue: list[dict] = []
        # Phase 20 P-A2: per-class applicability verdicts (evaluated lazily
        # once per scan in _build_engine_options).
        self.gate_report: Any = None
        # Phase 20 P-A1: task-level checkpoint state for the agent engine —
        # completed task ids + their serialized findings, persisted in
        # resume_data after every task (mid-engine checkpoint).
        self._completed_agent_tasks: list[str] = []
        self._partial_agent_findings: list[dict] = []
        self.adjudication_summary: Optional[Dict[str, Any]] = None

        # Statistics
        self.total_files = 0
        self.total_findings = 0
        self.total_tokens = 0
        self.start_time: Optional[datetime] = None

        # Token tracking for separation
        self._adversarial_tokens_used: int = 0  # Track tokens used by adversarial verification

        # Services (lazy initialization)
        self._attack_surface_service: Optional[AttackSurfaceService] = None
        self.incremental_scan_service: Optional[IncrementalScanService] = None
        self.incremental_files_to_scan: Optional[set] = None

    def _get_attack_surface_service(self) -> Optional[AttackSurfaceService]:
        """Get or create the AttackSurfaceService.

        P14-01: Lazy initialization of AttackSurfaceService.

        Returns:
            AttackSurfaceService instance if LLM client is available, None otherwise.
        """
        if self._attack_surface_service is None and self.llm_client:
            self._attack_surface_service = AttackSurfaceService(
                llm_client=self.llm_client,
                db_session=None,
            )
        return self._attack_surface_service

    def _build_scan_phases(self, ctx: ScanContext) -> list[PhaseSpec]:
        """Build the ordered scan phases driven by ScanPipeline.

        Each runner delegates to an existing ``_run_*`` helper (no behaviour
        change); each summary reproduces the exact progress payload the frontend
        expects. Conditional phases use ``skip_when``; ``checkpoint_key`` marks
        phases whose completion is persisted for resume (via WebCheckpointSink).
        """

        async def _l1(_ctx: ScanContext, _pl: ScanPipeline) -> None:
            await self._run_l1_preparation()

        async def _source(_ctx: ScanContext, _pl: ScanPipeline) -> None:
            await self._prepare_source()

        async def _engine_select(_ctx: ScanContext, _pl: ScanPipeline) -> None:
            ctx.extra["engines"] = await self._select_engines()

        async def _engine_exec(_ctx: ScanContext, _pl: ScanPipeline) -> None:
            await self._execute_engines(ctx.extra.get("engines") or {})
            details: dict[str, Any] = {}
            for name, result in self.scan_results.items():
                details[name] = {
                    "findings": len(result.findings),
                    "duration_seconds": getattr(result, "duration_seconds", 0) or 0,
                    "tokens_used": 0,
                }
                if isinstance(result.raw_output, dict):
                    details[name]["tokens_used"] = result.raw_output.get("total_tokens", 0)
                    if name == "agent":
                        details[name]["files_analyzed"] = result.raw_output.get("files_analyzed", 0)
                        details[name]["agent_total_files"] = result.raw_output.get("total_files", 0)
                        details[name]["analyzed_file_paths"] = result.raw_output.get("analyzed_file_paths", [])
                        # Phase 20 P-A1 transparency: task pool statistics.
                        if result.raw_output.get("task_summary"):
                            details[name]["task_summary"] = result.raw_output["task_summary"]
            # Phase 20 P-A2 transparency: per-class applicability verdicts.
            gate = self.gate_report
            if gate is not None:
                details["applicability_gate"] = {
                    "gated_classes": gate.gated_classes(),
                    "decisions": [d.to_dict() for d in gate.decisions],
                }
            ctx.extra["per_engine_details"] = details

        async def _exploit(_ctx: ScanContext, _pl: ScanPipeline) -> None:
            ctx.extra["verified_count"] = await self._run_exploitability_verification()

        async def _logic(_ctx: ScanContext, _pl: ScanPipeline) -> None:
            ctx.extra["logic_vuln_count"] = await self._run_logic_vuln_discovery()

        async def _adjudication(_ctx: ScanContext, _pl: ScanPipeline) -> None:
            ctx.extra["adjudication_summary"] = await self._run_adjudication()

        async def _adversarial(_ctx: ScanContext, _pl: ScanPipeline) -> None:
            ctx.extra["adversarial_summary"] = await self._run_adversarial_verification()

        async def _merge(_ctx: ScanContext, _pl: ScanPipeline) -> None:
            await self._finalize_results()

        async def _tokens(_ctx: ScanContext, _pl: ScanPipeline) -> None:
            ctx.extra["token_stats"] = await self._update_token_statistics()

        def _total_findings() -> int:
            return sum(len(r.findings) for r in self.scan_results.values())

        return [
            PhaseSpec(
                phase=ScanPhase.L1_PREPARATION,
                runner=_l1,
                summary=lambda c: {
                    "languages": self.tech_stack.get("languages", []),
                    "frameworks": self.tech_stack.get("frameworks", []),
                    "primary_language": self.tech_stack.get("primary_language"),
                    "total_files": self.tech_stack.get("total_files", 0),
                    "file_counts": self.tech_stack.get("file_counts", {}),
                    "attack_surface": self.attack_surface_report.get("total_entry_points", 0)
                    if self.attack_surface_report
                    else 0,
                },
            ),
            PhaseSpec(
                phase=ScanPhase.SOURCE_PREPARATION,
                runner=_source,
                summary=lambda c: {"total_files": self.total_files},
            ),
            PhaseSpec(
                phase=ScanPhase.ENGINE_SELECTION,
                runner=_engine_select,
                summary=lambda c: {"engines": list((c.extra.get("engines") or {}).keys())},
            ),
            PhaseSpec(
                phase=ScanPhase.ENGINE_EXECUTION,
                runner=_engine_exec,
                checkpoint_key="engine_execution",
                summary=lambda c: {
                    "findings": _total_findings(),
                    "per_engine_details": c.extra.get("per_engine_details") or {},
                },
            ),
            PhaseSpec(
                phase=ScanPhase.EXPLOITABILITY_VERIFICATION,
                runner=_exploit,
                skip_when=lambda c: not self.config.get("llm_verify", True),
                checkpoint_key="exploitability_verification",
                summary=lambda c: {"verified_findings": c.extra.get("verified_count", 0)},
            ),
            PhaseSpec(
                phase=ScanPhase.LOGIC_VULN_DISCOVERY,
                runner=_logic,
                skip_when=lambda c: not self.config.get("logic_vuln", False),
                summary=lambda c: {"logic_vuln_findings": c.extra.get("logic_vuln_count", 0)},
            ),
            PhaseSpec(
                phase=ScanPhase.ADJUDICATION,
                runner=_adjudication,
                checkpoint_key="deduplication_adjudication",
                summary=lambda c: {
                    "unique_findings": (c.extra.get("adjudication_summary") or {}).get("unique_findings", 0),
                    "duplicates_removed": (c.extra.get("adjudication_summary") or {}).get("duplicates_removed", 0),
                },
            ),
            PhaseSpec(
                phase=ScanPhase.ADVERSARIAL,
                runner=_adversarial,
                skip_when=lambda c: not self.config.get("adversarial", False),
                summary=lambda c: {
                    "verified_findings": (c.extra.get("adversarial_summary") or {}).get("verified_count", 0),
                    "confirmed": (c.extra.get("adversarial_summary") or {}).get("confirmed", 0),
                    "rejected": (c.extra.get("adversarial_summary") or {}).get("rejected", 0),
                },
            ),
            PhaseSpec(
                phase=ScanPhase.RESULT_MERGE,
                runner=_merge,
                checkpoint_key="result_merging",
                summary=lambda c: {"total_findings": self.total_findings},
            ),
            PhaseSpec(
                phase=ScanPhase.TOKEN_STATS,
                runner=_tokens,
                summary=lambda c: {
                    "total_tokens": (c.extra.get("token_stats") or {}).get("total_tokens", 0),
                    "estimated_cost": (c.extra.get("token_stats") or {}).get("estimated_cost", 0),
                },
            ),
        ]

    async def execute_scan(self, resume_from: str | None = None) -> Dict[str, Any]:
        """
        Execute the complete scan workflow.

        This is the main entry point that orchestrates all scan phases.

        Args:
            resume_from: Optional phase name to resume from. When set, the
                checkpoint for this scan is loaded and already-completed phases
                are recorded. (Full zero-rerun skip requires intermediate-state
                persistence, which is layered on top of this via the shared
                pipeline's CheckpointSink.)

        Returns:
            Dictionary with scan results:
                - success: bool
                - findings_count: int
                - duration_seconds: float
                - error: str | None

        Raises:
            Exception: If the scan fails critically
        """
        self.start_time = datetime.now(timezone.utc)

        # Resume support: load any prior checkpoint so progress is recorded and
        # resume_from is honored (no longer silently dropped).
        self._completed_phases: set[str] = set()
        self._checkpoint_service = None
        try:
            from src.web.services.checkpoint_service import get_checkpoint_service
            self._checkpoint_service = get_checkpoint_service()
            if resume_from:
                ckpt = await self._checkpoint_service.load_checkpoint(self.scan_id)
                if ckpt and await self._checkpoint_service.verify_checkpoint(ckpt):
                    strategy = await self._checkpoint_service.get_resume_strategy(ckpt)
                    self._completed_phases = set(strategy.skip_phases)
                    # D3: restore findings produced by completed (now-skipped)
                    # phases so downstream verification/adjudication have data.
                    self._restore_state_from_checkpoint(ckpt)
                    logger.info(
                        f"Scan {self.scan_id}: resuming from {resume_from}; "
                        f"previously completed phases: {sorted(self._completed_phases)}; "
                        f"restored {sum(len(r.findings) for r in self.scan_results.values())} findings"
                    )
        except Exception as e:
            logger.warning(f"Checkpoint load failed for scan {self.scan_id}: {e}")

        # Phase 20 resume fix: on a resumed scan _prepare_source is skipped,
        # so source_path would stay the raw constructor str and engines would
        # crash on Path operations (e.g. source_path.exists()). Normalize it
        # once, before any phase runs.
        if self.source_path is not None and not isinstance(self.source_path, Path):
            self.source_path = Path(str(self.source_path))

        # Set scan configuration for progress callback
        # This enables dynamic weight calculation for optional phases
        self.progress_callback.set_scan_config(self.config)

        # Start adaptive concurrency recovery loops
        agent_manager = None
        verify_manager = None
        _concurrency_broadcast_stop = None
        _concurrency_task = None
        try:
            from src.core.llm import (
                get_agent_scan_concurrency_manager_from_db,
                get_verification_concurrency_manager_from_db,
            )
            agent_manager = await get_agent_scan_concurrency_manager_from_db(self.db_session_factory)
            verify_manager = await get_verification_concurrency_manager_from_db(self.db_session_factory)
            await agent_manager.start_recovery_loop()
            await verify_manager.start_recovery_loop()

            # Register callbacks for real-time concurrency updates
            if self.progress_callback:
                def _make_callback(label: str):
                    def _on_change(old: int, new: int, mgr):
                        try:
                            asyncio.get_running_loop().create_task(
                                self.progress_callback.broadcast_event(
                                    event_type="concurrency_update",
                                    data={
                                        "manager": label,
                                        **mgr.get_adaptive_status(),
                                        "previous_concurrent": old,
                                    },
                                )
                            )
                        except RuntimeError:
                            pass
                    return _on_change

                agent_manager.on_concurrency_change(_make_callback("agent_scan"))
                verify_manager.on_concurrency_change(_make_callback("verification"))

                # Broadcast initial concurrency state so the frontend can display it
                # even before any throttling/recovery events occur
                if self.progress_callback:
                    for label, mgr in [("agent_scan", agent_manager), ("verification", verify_manager)]:
                        try:
                            await self.progress_callback.broadcast_event(
                                event_type="concurrency_update",
                                data={
                                    "manager": label,
                                    **mgr.get_adaptive_status(),
                                    "previous_concurrent": mgr.get_adaptive_status()["current_concurrent"],
                                },
                            )
                        except Exception:
                            pass

                # Periodically broadcast concurrency status (every 30s) so frontend
                # always has fresh data, not only when throttling/recovery occurs.
                _concurrency_broadcast_stop = asyncio.Event()

                async def _periodic_concurrency_broadcast():
                    while not _concurrency_broadcast_stop.is_set():
                        try:
                            await asyncio.wait_for(
                                _concurrency_broadcast_stop.wait(), timeout=30.0
                            )
                        except asyncio.TimeoutError:
                            pass  # timeout means 30s elapsed, broadcast now
                        if _concurrency_broadcast_stop.is_set():
                            break
                        if self.progress_callback:
                            for label, mgr in [
                                ("agent_scan", agent_manager),
                                ("verification", verify_manager),
                            ]:
                                try:
                                    await self.progress_callback.broadcast_event(
                                        event_type="concurrency_update",
                                        data={
                                            "manager": label,
                                            **mgr.get_adaptive_status(),
                                            "previous_concurrent": mgr.get_adaptive_status()["current_concurrent"],
                                        },
                                    )
                                except Exception:
                                    pass

                _concurrency_task = asyncio.create_task(_periodic_concurrency_broadcast())
        except Exception as e:
            logger.warning(f"Failed to initialize adaptive concurrency: {e}")

        try:
            # Drive the scan through ScanPipeline. Each phase delegates to the
            # existing _run_* helpers (see _build_scan_phases); summaries
            # reproduce the exact progress payloads the frontend expects. A
            # phase exception propagates here → on_scan_failed, preserving the
            # prior error contract of returning {success: False}.
            ctx = ScanContext(
                scan_id=self.scan_id,
                source_path=Path(str(self.source_path)),
                config=self.config,
            )
            pipeline = ScanPipeline(
                ctx,
                self._build_scan_phases(ctx),
                WebProgressSink(self.progress_callback),
                WebCheckpointSink(self),
            )
            await pipeline.execute(resume_from=resume_from)

            # Calculate duration
            duration_seconds = (
                datetime.now(timezone.utc) - self.start_time
            ).total_seconds()

            # Report completion
            tokens_used = 0
            if self.llm_client:
                usage = self.llm_client.get_total_usage()
                tokens_used = usage.total_tokens

            token_stats = ctx.extra.get("token_stats") or {}
            per_engine_details = ctx.extra.get("per_engine_details") or {}
            per_phase_tokens = {
                "agent_scan": token_stats.get("agent_scan_tokens", 0),
                "adversarial": self._adversarial_tokens_used,
                "total": token_stats.get("total_tokens", 0),
            }
            agent_detail = per_engine_details.get("agent", {})

            await self.progress_callback.on_scan_complete(
                self.total_findings, duration_seconds, tokens_used,
                per_phase_tokens=per_phase_tokens,
                agent_analyzed_files=agent_detail.get("analyzed_file_paths", []),
                agent_files_analyzed=agent_detail.get("files_analyzed", 0),
            )

            # Checkpoint is cleaned on full success by WebCheckpointSink.clean()
            # (invoked at the end of ScanPipeline.execute).
            return {
                "success": True,
                "findings_count": self.total_findings,
                "duration_seconds": duration_seconds,
            }

        except Exception as e:
            logger.exception(f"Scan {self.scan_id} failed: {e}")
            await self.progress_callback.on_scan_failed(str(e))
            await self._cleanup()
            return {
                "success": False,
                "error": str(e),
                "findings_count": 0,
                "duration_seconds": (
                    datetime.now(timezone.utc) - self.start_time
                ).total_seconds()
                if self.start_time
                else 0,
            }
        finally:
            await self._cleanup()
            # Stop periodic concurrency broadcast
            try:
                _concurrency_broadcast_stop.set()
                if _concurrency_task and not _concurrency_task.done():
                    _concurrency_task.cancel()
            except Exception:
                pass
            # Stop adaptive concurrency recovery loops
            try:
                if agent_manager:
                    await agent_manager.stop_recovery_loop()
                if verify_manager:
                    await verify_manager.stop_recovery_loop()
            except Exception:
                pass

    async def _save_checkpoint_phase(self, phase: str, data: dict | None = None) -> None:
        """Persist phase completion for resume support. Best-effort, never raises."""
        if not getattr(self, "_checkpoint_service", None):
            return
        try:
            await self._checkpoint_service.save_checkpoint(self.scan_id, phase, data or {})
        except Exception as e:
            logger.warning(f"Checkpoint save failed for phase {phase}: {e}")

    async def _clean_checkpoint(self) -> None:
        """Remove the scan checkpoint after successful completion."""
        if not getattr(self, "_checkpoint_service", None):
            return
        try:
            await self._checkpoint_service.clean_checkpoint(self.scan_id)
        except Exception as e:
            logger.warning(f"Checkpoint clean failed: {e}")

    # ------------------------------------------------------------------
    # D3: findings persistence for checkpoint resume
    # ------------------------------------------------------------------
    def _serialize_scan_results(self) -> list[dict[str, Any]]:
        """Serialize ``self.scan_results`` into a JSON-safe list for checkpointing.

        Each engine maps to ``{"engine": name, "scan_result": <model_dump>}``.
        ``mode="json"`` keeps the payload directly storable in the DB JSON
        column and the checkpoint file backup. Engines that fail to serialize
        are skipped (best-effort) so one bad engine never blocks a checkpoint.
        """
        out: list[dict[str, Any]] = []
        for engine, result in self.scan_results.items():
            try:
                out.append(
                    {"engine": engine, "scan_result": result.model_dump(mode="json")}
                )
            except Exception as exc:
                logger.warning(f"checkpoint: failed to serialize {engine} findings: {exc}")
        return out

    def _restore_scan_results(self, serialized: list[dict[str, Any]] | None) -> None:
        """Restore ``self.scan_results`` from a serialized list (resume path).

        Tolerant of missing/malformed entries: a single bad engine is skipped
        rather than aborting the resume.
        """
        if not serialized:
            return
        for entry in serialized:
            if not isinstance(entry, dict):
                continue
            engine = entry.get("engine")
            raw = entry.get("scan_result")
            if not engine or not isinstance(raw, dict):
                continue
            try:
                self.scan_results[engine] = ScanResult.model_validate(raw)
            except Exception as exc:
                logger.warning(f"checkpoint: failed to restore {engine} findings: {exc}")

    def _serialize_resume_data(self) -> dict[str, Any]:
        """Build the resume_data payload (single source of truth).

        Combines serialized scan_results with the per-engine completion set so
        a resumed scan can both skip completed phases AND skip individual
        completed engines within engine_execution (P7-C6). Every checkpoint
        save — phase-boundary (WebCheckpointSink) and mid-phase per-engine —
        routes through here, because ``save_checkpoint`` replaces resume_data
        wholesale rather than merging.
        """
        return {
            "scan_results": self._serialize_scan_results(),
            "completed_engines": sorted(self._completed_engines),
            # Phase 20 P-A1: task-granular agent progress (optional keys —
            # checkpoints written before this feature simply lack them).
            "completed_agent_tasks": list(self._completed_agent_tasks),
            "partial_agent_findings": list(self._partial_agent_findings),
            # Phase 20 resume fix: L1 products needed to rebuild the gate and
            # the deterministic task plan on a resumed orchestrator (the L1
            # phase itself is skipped on resume, leaving these unset).
            "tech_stack": {
                k: v for k, v in (self.tech_stack or {}).items()
                if k != "_full_stack"
            },
            "attack_surface_report": (
                self.attack_surface_report_obj.model_dump(mode="json")
                if self.attack_surface_report_obj is not None
                else None
            ),
        }

    async def _save_engine_checkpoint(self, engine_name: str) -> None:
        """Persist a mid-engine-execution checkpoint after an engine finishes.

        Best-effort: a failed save is logged, never raised (must not abort the
        scan). Records the engine as completed and snapshots resume_data so a
        crash before the phase completes still lets resume skip finished
        engines (especially expensive CodeQL).
        """
        self._completed_engines.add(engine_name)
        try:
            await self._save_checkpoint_phase(
                "engine_execution",
                {"resume_data": self._serialize_resume_data()},
            )
        except Exception as exc:  # noqa: BLE001 — best-effort checkpoint
            logger.warning(f"checkpoint: engine-level save failed for {engine_name}: {exc}")

    def _restore_state_from_checkpoint(self, ckpt: Any) -> None:
        """Restore resumable orchestrator state from a checkpoint.

        Restores scan_results (findings) AND the per-engine completion set. The
        completion set is intersected with the restored result engines so an
        engine is never marked completed without its output (defends against a
        checkpoint where completed_engines and scan_results drifted apart).
        """
        try:
            resume_data = getattr(ckpt, "resume_data", None) or {}
            self._restore_scan_results(resume_data.get("scan_results"))
            completed = resume_data.get("completed_engines") or []
            if isinstance(completed, list):
                restored_engines = set(self.scan_results.keys())
                self._completed_engines = set(completed) & restored_engines
            # Phase 20 P-A1: task-granular agent progress. Optional keys —
            # older checkpoints without them restore as empty (no migration).
            agent_tasks = resume_data.get("completed_agent_tasks") or []
            partial_findings = resume_data.get("partial_agent_findings") or []
            if "agent" not in self._completed_engines:
                if isinstance(agent_tasks, list):
                    self._completed_agent_tasks = [str(t) for t in agent_tasks]
                if isinstance(partial_findings, list):
                    self._partial_agent_findings = list(partial_findings)
                if self._completed_agent_tasks:
                    logger.info(
                        f"checkpoint: restored {len(self._completed_agent_tasks)} "
                        f"completed agent task(s), "
                        f"{len(self._partial_agent_findings)} partial finding(s)"
                    )
            # Phase 20 resume fix: restore L1 products so the applicability
            # gate and the deterministic task plan rebuild identically.
            restored_ts = resume_data.get("tech_stack")
            if isinstance(restored_ts, dict) and restored_ts and not self.tech_stack:
                self.tech_stack = dict(restored_ts)
            restored_as = resume_data.get("attack_surface_report")
            if (
                isinstance(restored_as, dict)
                and self.attack_surface_report_obj is None
            ):
                try:
                    self.attack_surface_report_obj = AttackSurfaceReport.model_validate(
                        restored_as
                    )
                except Exception as exc:
                    logger.warning(f"checkpoint: attack surface restore failed: {exc}")
        except Exception as exc:
            logger.warning(f"checkpoint: state restore failed: {exc}")

    # ========================================================================
    # Source Preparation
    # ========================================================================

    async def _prepare_source(self) -> None:
        """
        Prepare the source code for scanning.

        Handles:
        - ZIP file extraction (like DeepAudit's process_zip_task)
        - Directory structure detection
        - File filtering and counting

        Optimization: Reuses extracted directory from Phase 0 if available.

        Reference: DeepAudit scanner.py:297-350 (process_zip_task)
        """
        # Check if source_path was already set by Phase 0 (L1_Preparation)
        if self.source_path is not None:
            logger.info(f"Scan {self.scan_id}: Reusing extracted directory from Phase 0: {self.source_path}")
            # Update total_files count
            self.total_files = self._count_code_files()
            logger.info(f"Scan {self.scan_id}: {self.total_files} code files in {self.source_path}")
            return

        # Need to extract source (this happens when Phase 0 was skipped or source is not a ZIP)
        # Read source_path from the scan record
        async with self.db_session_factory() as db:
            from src.web.repositories.scan import ScanRepository
            scan_repo = ScanRepository()
            scan = await scan_repo.get(db, id=self.scan_id)
            if not scan:
                raise ValueError(f"Scan {self.scan_id} not found")

        source_path = Path(scan.source_path)

        # Handle ZIP files
        if source_path.suffix == ".zip":
            self.temp_dir = Path(
                tempfile.mkdtemp(prefix=f"deepvuln_scan_{self.scan_id}_")
            )

            try:
                logger.info(f"Extracting ZIP: {source_path} -> {self.temp_dir}")
                safe_unpack_archive(source_path, self.temp_dir)

                # Find actual code directory
                self.source_path = self._find_code_directory(self.temp_dir)
                logger.info(f"Using code directory: {self.source_path}")

            except Exception as e:
                # Cleanup on failure
                if self.temp_dir and self.temp_dir.exists():
                    shutil.rmtree(self.temp_dir, ignore_errors=True)
                raise ValueError(f"Failed to extract ZIP: {e}")
        else:
            self.source_path = source_path

        # P14-06: Incremental scan mode
        if self.config.get("incremental", False):
            await self._prepare_incremental_scan()

        # Count total files (with basic filtering)
        self.total_files = self._count_code_files()
        logger.info(f"Scan {self.scan_id}: {self.total_files} code files in {self.source_path}")

    def _find_code_directory(self, extracted_dir: Path) -> Path:
        """
        Find the actual code directory from extracted ZIP.

        Implements smart directory detection similar to DeepAudit:
        - Single subdirectory -> use that
        - Project markers (package.json, pom.xml, etc.) -> use that
        - Default -> use root

        Reference: DeepAudit scanner.py extraction logic
        """
        items = list(extracted_dir.iterdir())

        # Single directory
        if len(items) == 1 and items[0].is_dir():
            return items[0]

        # Look for project markers
        markers = [
            "package.json",
            "pom.xml",
            "build.gradle",
            "requirements.txt",
            "go.mod",
            "Cargo.toml",
            "setup.py",
            "pyproject.toml",
            "Gemfile",
            "composer.json",
        ]

        for item in items:
            if item.is_dir():
                for marker in markers:
                    if (item / marker).exists():
                        return item

        # Default: use root directory
        return extracted_dir

    def _count_code_files(self) -> int:
        """
        Count code files while excluding common non-code directories.

        Excludes:
        - Version control (.git, .svn)
        - Dependencies (node_modules, vendor, __pycache__)
        - Build artifacts (dist, build, target)
        - IDE files (.idea, .vscode)
        - Documentation (docs, *_examples.md)

        Returns:
            Count of code files
        """
        exclude_dirs = {
            ".git", ".svn", ".hg",
            "node_modules", "vendor", "__pycache__",
            ".venv", "venv", "env", ".env",
            "dist", "build", "target", "out",
            ".idea", ".vscode", ".eclipse",
            "coverage", ".nyc_output",
            ".pytest_cache", ".mypy_cache",
            "bin", "obj", ".gradle",
        }

        exclude_files = {
            ".gitignore", ".dockerignore",
            "*.min.js", "*.min.css",
            "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
            "*.gz", "*.zip", "*.tar",
            "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg",
            "*.pdf", "*.doc", "*.docx",
        }

        count = 0
        for item in self.source_path.rglob("*"):
            # Skip excluded directories
            if any(part in exclude_dirs for part in item.parts):
                continue

            # Count files only (not directories)
            if item.is_file():
                # Check file extension
                ext = item.suffix.lower()
                # Skip common non-code extensions
                if ext in {'.min.js', '.min.css', '.map', '.lock', '.gz',
                          '.zip', '.tar', '.png', '.jpg', '.jpeg', '.gif',
                          '.ico', '.svg', '.pdf', '.doc', '.docx', '.exe',
                          '.dll', '.so', '.dylib', '.class', '.pyc'}:
                    continue

                # Skip specific file names
                if item.name in {'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
                                '.gitignore', '.dockerignore', 'LICENSE', 'README.md',
                                'README.rst', 'CONTRIBUTING.md'}:
                    continue

                count += 1

        return count

    async def _prepare_incremental_scan(self) -> None:
        """Prepare incremental scan by analyzing Git changes (P14-06).

        This method:
        1. Creates IncrementalScanService
        2. Analyzes Git changes between base_ref and head_ref
        3. Stores the list of files to scan for filtering

        Raises:
            ValueError: If not a Git repository or Git operations fail
        """
        from pathlib import Path as PathLib

        # Get incremental scan configuration
        base_ref = self.config.get("base_ref", "HEAD~1")
        head_ref = self.config.get("head_ref", "HEAD")

        logger.info(
            f"Preparing incremental scan: {base_ref}...{head_ref}"
        )

        # Create incremental scan service
        self.incremental_scan_service = IncrementalScanService(
            scan_id=self.scan_id,
        )

        # Analyze changes
        try:
            context = await self.incremental_scan_service.analyze_incremental_changes(
                source_path=PathLib(self.source_path),
                base_ref=base_ref,
                head_ref=head_ref,
            )

            # Store context for later use
            self.incremental_scan_service.context = context

            # Get files to scan
            self.incremental_files_to_scan = (
                self.incremental_scan_service.get_files_to_scan()
            )

            logger.info(
                f"Incremental scan: {len(self.incremental_files_to_scan)} files to scan "
                f"({context.added_files} added, {context.modified_files} modified)"
            )

            # Update progress
            await self.progress_callback.on_phase_start("incremental_analysis")
            await self.progress_callback.on_phase_complete(
                "incremental_analysis",
                {
                    "files_to_scan": len(self.incremental_files_to_scan),
                    "added_files": context.added_files,
                    "modified_files": context.modified_files,
                }
            )

        except Exception as e:
            logger.error(f"Incremental scan analysis failed: {e}")
            # P14-06e: Failure should terminate the scan (no auto-degrade)
            raise ValueError(
                f"Incremental scan failed: {e}. "
                f"Please ensure the source is a Git repository and refs are valid."
            ) from e

    # ========================================================================
    # Tech Stack Detection
    # ========================================================================

    async def _detect_tech_stack(self) -> Dict[str, Any]:
        """
        Detect the project's technology stack using TechStackDetector.

        Returns:
            Dictionary with comprehensive tech stack information
        """
        return await self._detect_tech_stack_impl()

    # ========================================================================
    # Engine Selection
    # ========================================================================

    async def _select_engines(self) -> Dict[str, BaseEngine]:
        """
        Select appropriate analysis engines based on config and tech stack.

        Returns:
            Dictionary of {engine_name: engine_instance}
        """
        from src.layers.l3_analysis.engines.semgrep import SemgrepEngine
        from src.layers.l3_analysis.engines.codeql import CodeQLEngine
        from src.layers.l3_analysis.engines.opencode_agent import OpenCodeAgent

        selected_engines = {}
        from src.web.models.schemas import DEFAULT_SCAN_ENGINES
        requested = self.config.get("engines") or list(DEFAULT_SCAN_ENGINES)

        # Semgrep - always available if requested
        if "semgrep" in requested:
            engine = SemgrepEngine()
            if engine.is_available():
                selected_engines["semgrep"] = engine
                logger.info(f"Scan {self.scan_id}: Semgrep engine selected")

        # CodeQL - check availability
        if "codeql" in requested:
            engine = CodeQLEngine()
            if engine.is_available():
                # Quick readiness check (P6-02)
                try:
                    readiness = await self._check_codeql_readiness(engine)
                    if readiness["ready"]:
                        selected_engines["codeql"] = engine
                        logger.info(f"Scan {self.scan_id}: CodeQL engine selected")
                    else:
                        await self.progress_callback.on_warning(
                            f"CodeQL not ready: {readiness['message']}"
                        )
                except Exception as e:
                    await self.progress_callback.on_warning(
                        f"CodeQL check failed: {e}"
                    )

        # Agent - check LLM config
        if "agent" in requested:
            # 只有在配置了 LLM 客户端时才启用 agent
            if self.llm_client and self.llm_client.is_available:
                # P3-05: Create CPGPathProvider for attack path analysis
                cpg_path_provider = None
                try:
                    from src.layers.l3_analysis.engines.ast_engine.cpg.path_provider import CPGPathProvider
                    cpg_path_provider = CPGPathProvider()
                    logger.info(f"Scan {self.scan_id}: CPGPathProvider created for agent engine")
                except Exception as e:
                    logger.warning(f"Scan {self.scan_id}: CPGPathProvider unavailable: {e}")

                engine = OpenCodeAgent(
                    llm_client=self.llm_client,
                    cpg_path_provider=cpg_path_provider,
                )
                selected_engines["agent"] = engine
                logger.info(f"Scan {self.scan_id}: Agent engine selected")
            else:
                logger.warning(f"Scan {self.scan_id}: Agent engine requested but no LLM client available")

        # AST Engine - if available
        if "ast" in requested:
            from src.layers.l3_analysis.engines.ast_engine.ast_engine import (
                ASTEngine,
            )

            engine = ASTEngine()
            if engine.is_available():
                selected_engines["ast"] = engine
                logger.info(f"Scan {self.scan_id}: AST engine selected")

        if not selected_engines:
            raise RuntimeError("No analysis engines available")

        return selected_engines

    async def _check_codeql_readiness(
        self, engine: "CodeQLEngine"
    ) -> Dict[str, Any]:
        """Check CodeQL readiness with timeout."""
        try:
            return await asyncio.wait_for(
                engine.check_readiness(
                    self.source_path,
                    startup_timeout=15,
                ),
                timeout=20,
            )
        except asyncio.TimeoutError:
            return {"ready": False, "message": "Readiness check timed out"}

    # ========================================================================
    # Engine Execution
    # ========================================================================

    async def _execute_engines(self, engines: Dict[str, BaseEngine]) -> None:
        """
        Execute engines concurrently, checkpointing each as it finishes.

        Implements the concurrent execution strategy:
        - CodeQL (CPU intensive) runs separately
        - Semgrep, Agent, AST run concurrently

        Reference: Plan Section 4.1 - Engine Grouping Strategy

        P7-C6: engines already in ``_completed_engines`` (resumed mid-phase)
        are skipped, and a mid-phase checkpoint is written as each engine
        finishes so a crash before the phase completes lets resume skip
        finished engines (especially expensive CodeQL).

        P7-C6 Tier2: the concurrent batch uses ``asyncio.wait`` with
        ``FIRST_COMPLETED`` so each engine is checkpointed the moment it
        finishes — a crash mid-batch then only re-runs the still-pending
        engines, not the whole batch (Tier1 gathered first).

        Phase 20 resume fix: on a resume from engine_execution the
        ENGINE_SELECTION phase is skipped, leaving ``engines`` empty — the
        phase would previously complete as a no-op (0 findings, 0 tokens).
        Re-select engines so the pending set (and P-A1 task-level resume
        inside the agent engine) can actually run.
        """
        if not engines:
            engines = await self._select_engines()
            if engines:
                logger.info(
                    f"Scan {self.scan_id}: engine_execution re-selected engines "
                    f"{list(engines)} (resume path)"
                )
        # P7-C6: skip engines already completed on a prior (interrupted) run.
        # Their results were restored into scan_results from the checkpoint.
        pending = {
            name: engine
            for name, engine in engines.items()
            if name not in self._completed_engines
        }

        # Split pending engines by execution strategy
        cpu_intensive = {}
        concurrent_engines = {}

        for name, engine in pending.items():
            if name == "codeql":
                cpu_intensive[name] = engine
            else:
                concurrent_engines[name] = engine

        # Execute CPU-intensive engines first (CodeQL) — checkpoint after each.
        if cpu_intensive:
            for name, engine in cpu_intensive.items():
                try:
                    await self.progress_callback.on_engine_start(name)
                    result = await self._run_engine_with_timeout(name, engine)
                    self.scan_results[name] = result
                    await self.progress_callback.on_engine_complete(
                        name,
                        len(result.findings),
                        result.duration_seconds or 0,
                    )
                    await self._save_engine_checkpoint(name)
                except Exception as e:
                    await self.progress_callback.on_engine_failed(name, str(e))

        # Execute other engines concurrently — Tier2: checkpoint each engine
        # the moment it finishes (asyncio.wait FIRST_COMPLETED), instead of
        # gathering the whole batch first. A crash mid-batch then only
        # re-runs still-pending engines on resume, not the entire batch.
        if concurrent_engines:
            pending_tasks = {
                asyncio.create_task(
                    self._run_engine_concurrent(name, engine)
                ): name
                for name, engine in concurrent_engines.items()
            }

            while pending_tasks:
                done, _ = await asyncio.wait(
                    set(pending_tasks),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for finished in done:
                    name = pending_tasks.pop(finished)
                    try:
                        result = finished.result()
                    except Exception as e:
                        await self.progress_callback.on_engine_failed(
                            name, str(e)
                        )
                        continue
                    if result:
                        self.scan_results[name] = result
                        await self.progress_callback.on_engine_complete(
                            name,
                            len(result.findings),
                            result.duration_seconds or 0,
                        )
                        await self._save_engine_checkpoint(name)

    async def _run_engine_with_timeout(
        self, name: str, engine: BaseEngine
    ) -> ScanResult:
        """Run an engine with timeout protection."""
        timeout = self._get_engine_timeout(name)

        try:
            return await asyncio.wait_for(
                self._run_engine(name, engine),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            raise TimeoutError(f"Engine {name} timed out after {timeout}s")

    async def _run_engine_concurrent(
        self, name: str, engine: BaseEngine
    ) -> ScanResult:
        """Run an engine in concurrent mode."""
        timeout = self._get_engine_timeout(name)

        try:
            return await asyncio.wait_for(
                self._run_engine(name, engine),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            raise TimeoutError(f"Engine {name} timed out after {timeout}s")

    async def _run_engine(self, name: str, engine: BaseEngine) -> ScanResult:
        """Run a single engine and collect findings."""
        logger.info(f"Scan {self.scan_id}: Running {name} engine")

        # Build scan options based on engine type
        options = await self._build_engine_options(name, engine)

        # Execute scan
        result = await engine.scan(self.source_path, **options)

        # Report findings as they are discovered
        for finding in result.findings:
            await self.progress_callback.on_finding(finding)

        return result

    def _evaluate_applicability_gate(self) -> Any:
        """Evaluate the P-A2 applicability gate (once per scan, lazily).

        Fail-open by construction: any error leaves ``gate_report`` as None
        and every consumer treats None as "no gating".
        """
        if self.gate_report is not None:
            return self.gate_report
        if not self.config.get("applicability_gate", True):
            return None
        try:
            from src.core.applicability_gate import evaluate_applicability

            self.gate_report = evaluate_applicability(
                tech_stack=self.tech_stack,
                attack_surface=self.attack_surface_report_obj,
                source_path=Path(str(self.source_path)),
            )
            gated = self.gate_report.gated_classes()
            if gated:
                logger.info(
                    f"Scan {self.scan_id}: applicability gate gated classes: {gated}"
                )
            return self.gate_report
        except Exception as e:
            logger.warning(
                f"Scan {self.scan_id}: applicability gate failed (fail-open): {e}"
            )
            return None

    def _build_task_plan(self) -> Optional[Dict[str, Any]]:
        """Build the P-A1 task plan from the gate + attack surface.

        Returns None whenever taskification should not run (gate disabled,
        planner error, empty plan) — the agent engine then keeps its flat
        behaviour, which also keeps the mini benchmark byte-identical.
        """
        if self.attack_surface_report_obj is None:
            return None
        try:
            from src.layers.l1_intelligence.attack_surface.task_planner import (
                TaskPlanner,
            )

            gate = self._evaluate_applicability_gate()
            planner = TaskPlanner(
                attack_surface=self.attack_surface_report_obj,
                gate_report=gate,
                tech_stack=self.tech_stack,
                max_tasks=int(self.config.get("max_tasks", 8)),
            )
            plan = planner.plan(Path(str(self.source_path)))
            if plan.is_empty:
                return None
            return plan.model_dump(mode="json")
        except Exception as e:
            logger.warning(
                f"Scan {self.scan_id}: task planning failed (flat fallback): {e}"
            )
            return None

    async def _on_agent_task_complete(
        self, task_id: str, findings_payloads: list[dict]
    ) -> None:
        """Task-level checkpoint callback (P7-C6 granularity, inside agent).

        Records the task as completed and snapshots resume_data so a crash
        mid-agent-phase resumes with the finished tasks skipped and their
        findings intact ("失败也推进检查点", the Codebuddy lesson).
        """
        if task_id not in self._completed_agent_tasks:
            self._completed_agent_tasks.append(task_id)
        self._partial_agent_findings.extend(findings_payloads or [])
        try:
            # Same payload contract as _save_engine_checkpoint: the
            # resume_data snapshot must ride along, otherwise the checkpoint
            # is written with an empty resume_data and resume loses the
            # completed tasks, their findings, and the L1 products.
            await self._save_checkpoint_phase(
                "engine_execution",
                {
                    "task_progress": {
                        "completed_tasks": len(self._completed_agent_tasks),
                        "last_completed": task_id,
                    },
                    "resume_data": self._serialize_resume_data(),
                },
            )
            logger.info(
                f"Scan {self.scan_id}: task checkpoint saved "
                f"({len(self._completed_agent_tasks)} tasks done, "
                f"{len(self._partial_agent_findings)} partial findings)"
            )
        except Exception as e:
            logger.warning(
                f"Scan {self.scan_id}: task checkpoint save failed (continuing): {e}"
            )

    async def _build_engine_options(
        self, name: str, engine: BaseEngine
    ) -> Dict[str, Any]:
        """Build engine-specific scan options using tech stack information."""
        options = {}

        if name == "semgrep":
            # Basic tech stack info
            options["tech_stack"] = self.tech_stack
            options["use_rule_gating"] = True
            options["use_finding_budget"] = True
            # Load the Semgrep registry rules. Without an explicit config source
            # Semgrep falls back to its minimal built-in defaults and finds
            # nothing — the Web main path returned 0 findings because this was
            # missing (the CLI path worked only because it set rule sets itself).
            options["use_auto_config"] = True
            # Phase 20 fix: the Web path never passed the attack surface, so
            # RuleGatingEngine silently ran fail-open without surface info.
            if self.attack_surface_report_obj is not None:
                options["attack_surface"] = self.attack_surface_report_obj

            # P-A2 convergence point: gate-not-applicable rule keywords merge
            # into the existing RuleGating exclusion list (extend, not replace).
            gate = self._evaluate_applicability_gate()
            if gate is not None:
                keywords = gate.disabled_rule_keywords()
                if keywords:
                    options["extra_disabled_rule_ids"] = keywords

            # Framework-aware rule selection
            frameworks = self.tech_stack.get("frameworks", [])
            if frameworks:
                options["target_frameworks"] = frameworks
                logger.info(
                    f"Scan {self.scan_id}: Targeting frameworks: {frameworks}"
                )

            # Test file filtering - optional based on config
            skip_tests = self.config.get("skip_tests", False)
            has_tests = self.tech_stack.get("has_tests", False)
            if skip_tests and has_tests:
                options["exclude_patterns"] = [
                    "*/tests/*",
                    "*/test_*",
                    "*/__tests__/*",
                    "*/spec/*",
                ]
                logger.info(f"Scan {self.scan_id}: Excluding test files")

        elif name == "codeql":
            # Check if multi-language project
            is_multi_lang = await self._is_multi_language_project()
            if is_multi_lang:
                options["multi_language"] = True
                options["languages"] = self.tech_stack.get("languages", [])
                logger.info(
                    f"Scan {self.scan_id}: CodeQL multi-language mode: "
                    f"{options['languages']}"
                )

            # Use primary language for single-language projects
            primary_language = self.tech_stack.get("primary_language")
            if primary_language and not is_multi_lang:
                options["primary_language"] = primary_language
                logger.info(
                    f"Scan {self.scan_id}: CodeQL primary language: {primary_language}"
                )

        elif name == "agent":
            options["max_files"] = self.config.get("agent_max_files", 50)
            options["tech_stack"] = self.tech_stack

            # IMPORTANT: Pass orchestrator's LLM client to agent engine
            # This ensures token usage is tracked consistently
            if self.llm_client:
                options["llm_client"] = self.llm_client
                logger.info(f"Scan {self.scan_id}: Passing LLM client to agent engine")

            # Add database context for more informed analysis
            databases = self.tech_stack.get("databases", [])
            if databases:
                options["detected_databases"] = databases
                logger.info(f"Scan {self.scan_id}: Agent aware of databases: {databases}")

            # Add middleware context (API gateways, message queues, etc.)
            middleware = self.tech_stack.get("middleware", [])
            if middleware:
                options["detected_middleware"] = middleware

            # Framework-specific analysis hints
            frameworks = self.tech_stack.get("frameworks", [])
            if frameworks:
                options["detected_frameworks"] = frameworks

            # Phase 20 P-A1: attack-surface taskified audit. Only when the
            # gate + planner produce a non-empty plan; otherwise the engine's
            # flat path runs exactly as before (auto-fallback).
            if self.config.get("task_split", True):
                plan = self._build_task_plan()
                if plan is not None and plan.get("tasks"):
                    options["task_plan"] = plan
                    options["resume_completed_tasks"] = list(self._completed_agent_tasks)
                    options["resume_findings"] = list(self._partial_agent_findings)
                    options["on_task_complete"] = self._on_agent_task_complete
                    options["task_concurrency"] = int(
                        self.config.get("task_concurrency", 2)
                    )
                    logger.info(
                        f"Scan {self.scan_id}: agent task plan active "
                        f"({len(plan['tasks'])} tasks)"
                    )

        elif name == "ast":
            # AST engine benefits from knowing the primary language
            primary_language = self.tech_stack.get("primary_language")
            if primary_language:
                options["primary_language"] = primary_language

        return options

    async def _is_multi_language_project(self) -> bool:
        """Check if this is a multi-language project."""
        languages = self.tech_stack.get("languages", [])
        return len(languages) > 1

    def _get_engine_timeout(self, engine_name: str) -> int:
        """Get timeout for an engine (in seconds)."""
        timeouts = {
            "semgrep": 300,  # 5 minutes
            "codeql": 1800,  # 30 minutes
            "agent": 600,  # 10 minutes
            "ast": 120,  # 2 minutes
        }
        return timeouts.get(engine_name, 300)

    # ========================================================================
    # Results Processing
    # ========================================================================

    async def _run_logic_vuln_discovery(self) -> int:
        """E5: AI supplement pass for logic vulnerabilities static tools miss.

        Opt-in (``logic_vuln`` config flag, default off). Feeds only
        entry-point-reachable regions to the LLM and emits grounded findings
        tagged ``source="logic_vuln"``. Runs after exploitability so logic
        findings skip taint verification and merge into adjudication directly.

        Returns:
            Number of logic-vulnerability findings discovered.
        """
        from src.layers.l3_analysis.engines.logic_vuln_detector import (
            LogicVulnerabilityDetector,
        )

        if not self.llm_client:
            logger.info("logic_vuln: skipped (no LLM client)")
            return 0
        if not self.attack_surface_report_obj:
            logger.info("logic_vuln: skipped (no attack surface report)")
            return 0

        detector = LogicVulnerabilityDetector(
            source_path=Path(str(self.source_path)),
            llm_client=self.llm_client,
            attack_surface_report=self.attack_surface_report_obj,
            config=self.config,
        )
        try:
            findings = await detector.discover()
        except Exception as exc:  # noqa: BLE001 — supplement pass must not abort the scan
            logger.warning(f"logic_vuln discovery failed: {exc}")
            return 0

        if findings:
            self.scan_results["logic_vuln"] = ScanResult(
                engine="logic_vuln",
                source_path=str(self.source_path),
                findings=findings,
                total_findings=len(findings),
                status="completed",
            )
        logger.info(f"logic_vuln: discovered {len(findings)} finding(s)")
        return len(findings)

    async def _run_exploitability_verification(self) -> int:
        """Run exploitability verification on findings (P14-02).

        Returns:
            Number of findings verified
        """
        from src.layers.l3_analysis.models import Finding

        # Get verification configuration
        llm_verify = self.config.get("llm_verify", True)
        if not llm_verify:
            logger.info("LLM verification disabled (llm_verify=False)")
            return 0

        if not self.scan_results:
            logger.info("No findings to verify")
            return 0

        # Multi-round audit (experimental): drive the full RoundController
        # (rounds 1-4) when ``enable_full_rounds`` is set. Rounds 1-3 were
        # previously unreachable; this wires them in behind a flag. On any
        # failure we fall back to the standard single Round-4 verification, so
        # the scan is never broken. Default off = current behavior unchanged.
        if self.config.get("enable_full_rounds", False):
            try:
                return await self._run_full_rounds_audit()
            except Exception as e:
                logger.warning(
                    f"Full multi-round audit failed ({e}); "
                    f"falling back to Round-4 verification"
                )

        # Collect all findings from all engines
        all_findings: list[Finding] = []
        for engine_name, scan_result in self.scan_results.items():
            all_findings.extend(scan_result.findings)

        if not all_findings:
            logger.info("No findings to verify")
            return 0

        logger.info(f"Verifying {len(all_findings)} findings for exploitability")

        # Get CodeQL findings for dataflow analysis
        codeql_findings = []
        if "codeql" in self.scan_results:
            codeql_findings = self.scan_results["codeql"].findings
            logger.info(f"Using {len(codeql_findings)} CodeQL findings for dataflow analysis")

        # Create verification service
        verification_service = create_verification_service(
            source_path=self.source_path,
            llm_client=self.llm_client,
            attack_surface_report=self.attack_surface_report_obj,
            codeql_findings=codeql_findings,
            enable_llm_assessment=True,
        )

        # Verify findings in batch
        # P18: Use concurrency manager with config from database
        from src.core.llm import get_agent_scan_concurrency_manager_from_db
        concurrency_manager = await get_agent_scan_concurrency_manager_from_db(self.db_session_factory)
        verification_results = await verification_service.verify_findings_batch(
            findings=all_findings,
            max_concurrent=concurrency_manager.max_concurrent,
        )

        # Apply verification results to findings
        verified_count = 0
        total_to_verify = len(verification_results)
        for finding in all_findings:
            if finding.id not in verification_results:
                continue

            result = verification_results[finding.id]
            # Store verification result in finding metadata
            finding.metadata = finding.metadata or {}
            exploit_dict = verification_service.create_exploitability_dict(result)
            finding.metadata["exploitability_verification"] = exploit_dict
            verified_count += 1

            # Broadcast per-finding verification result
            await self.progress_callback.broadcast_event("verification_result", {
                "finding_id": finding.id or "unknown",
                "finding_title": getattr(finding, 'title', '') or '',
                "status": exploit_dict.get("status", ""),
                "confidence": result.confidence,
                "reasoning": getattr(result, 'reasoning', '') or '',
            })

            # Push fine-grained progress
            if total_to_verify > 0:
                pct = int(verified_count / total_to_verify * 100)
                await self.progress_callback.on_progress(
                    pct,
                    f"可利用性验证 {verified_count}/{total_to_verify}",
                    phase_name="exploitability_verification",
                )

            logger.debug(
                f"Finding {finding.id}: {result.status.value} "
                f"(confidence: {result.confidence:.2f})"
            )

        logger.info(f"Verified {verified_count} findings for exploitability")
        return verified_count

    async def _run_full_rounds_audit(self) -> int:
        """Drive the full 4-round audit via RoundController (experimental).

        Rounds 1-3 (reconnaissance / CodeQL dataflow / evidence correlation)
        plus Round 4 (exploitability calibration) were previously dead code —
        only Round 4's ``_verify_exploitability`` was called directly. This
        wires the whole controller in, behind the ``enable_full_rounds`` flag.

        Any exception propagates to the caller, which falls back to single
        Round-4 verification, so the scan is never broken by an issue in the
        (previously unexercised) Round 1-3 path.
        """
        from src.layers.l3_analysis.rounds.controller import RoundController
        from src.layers.l3_analysis.rounds.round_one import RoundOneExecutor
        from src.layers.l3_analysis.rounds.round_two import RoundTwoExecutor
        from src.layers.l3_analysis.rounds.round_three import RoundThreeExecutor
        from src.layers.l3_analysis.rounds.round_four import RoundFourExecutor
        from src.layers.l3_analysis.strategy.engine import StrategyEngine

        codeql_findings = (
            self.scan_results["codeql"].findings if "codeql" in self.scan_results else []
        )
        # Reuse Agent findings the main scan already produced: seed them into
        # Round 1 so the multi-round audit adjudicates them without re-running
        # the Agent engine (D4 follow-up).
        agent_findings = (
            self.scan_results["agent"].findings if "agent" in self.scan_results else []
        )

        # Build an audit strategy from the attack surface (falls back to
        # file-based targets inside the engine if no attack surface).
        strategy_engine = StrategyEngine()
        strategy = strategy_engine.create_strategy(
            source_path=self.source_path,
            attack_surface=self.attack_surface_report_obj,
        )

        r1 = RoundOneExecutor(
            source_path=self.source_path, seed_findings=agent_findings
        )
        r2 = RoundTwoExecutor(source_path=self.source_path)
        r3 = RoundThreeExecutor(source_path=self.source_path)
        r4 = RoundFourExecutor(
            source_path=self.source_path,
            llm_client=self.llm_client,
            enable_llm_assessment=True,
            attack_surface_report=self.attack_surface_report_obj,
            codeql_results=codeql_findings,
        )
        executors = {1: r1, 2: r2, 3: r3, 4: r4}

        def executor_factory(round_number: int):
            return executors.get(round_number, r4).execute

        def _on_round_complete(result):
            try:
                asyncio.create_task(
                    self.progress_callback.broadcast_event(
                        "round_complete",
                        {
                            "round": getattr(result, "round_number", 0),
                            "candidates": getattr(result, "total_candidates", 0),
                        },
                    )
                )
            except Exception:
                pass

        controller = RoundController(max_rounds=4, on_round_complete=_on_round_complete)
        controller.start_session(
            self.source_path, strategy, project_name=self.source_path.name
        )
        session = await controller.execute_all_rounds(executor_factory)

        # Map exploitability verdicts from the session back onto engine findings.
        verified = 0
        for candidate in getattr(session, "all_candidates", []) or []:
            finding = getattr(candidate, "finding", None)
            if finding is None:
                continue
            finding.metadata = finding.metadata or {}
            finding.metadata["exploitability_verification"] = (
                candidate.to_exploitability_verification_metadata()
            )
            verified += 1

        logger.info(
            f"Multi-round audit completed: "
            f"{len(getattr(session, 'all_candidates', []) or [])} candidates, "
            f"{verified} mapped to findings"
        )
        return verified

    def _split_review_queue(
        self, findings: list[Finding]
    ) -> tuple[list[Finding], list[Finding]]:
        """Partition findings into reportable main set and review-only queue (P3).

        Agent low-confidence ``suspicious_code`` entries are marked
        ``metadata["is_suspicious"]=True`` and sneak into the final report as
        near-guaranteed false positives: the first mini baseline showed 26 FP
        mostly from such entries (confidence 0.1–0.5, adjudicated to
        ``conditional``). Unless ``include_suspicious_findings`` is enabled in
        the scan config, they are pulled out of adjudication and kept in the
        agent engine's metadata for manual review instead of being reported.

        Phase 20 P-A2: findings whose vulnerability class the applicability
        gate marked not-applicable (``metadata["gate_suppressed"]`` set by
        ``_apply_gate_suppression``) are pulled out the same way, with their
        own escape hatch (``include_gated_findings``).

        Returns:
            (main_findings, review_findings). ``main_findings`` is empty when
            every finding is review-only.
        """
        main: list[Finding] = []
        review: list[Finding] = []
        include_suspicious = self.config.get("include_suspicious_findings", False)
        include_gated = self.config.get("include_gated_findings", False)
        for finding in findings:
            metadata = finding.metadata or {}
            if metadata.get("is_suspicious") and not include_suspicious:
                review.append(finding)
            elif metadata.get("gate_suppressed") and not include_gated:
                review.append(finding)
            else:
                main.append(finding)
        return main, review

    def _apply_gate_suppression(self, findings: list[Finding]) -> None:
        """Mark P-A2 gate-not-applicable findings in place (pre-partition).

        Only classes with explicit high-confidence negative evidence are
        suppressed; the matched class + reason land in ``metadata`` so the
        suppression is auditable rather than silent.
        """
        gate = self.gate_report
        if gate is None:
            return
        gated_classes = gate.gated_classes()
        if not gated_classes:
            return
        from src.core.applicability_gate import finding_matches_gated_class

        for finding in findings:
            match = finding_matches_gated_class(finding.rule_id, gated_classes)
            if match:
                finding.metadata["gate_suppressed"] = (
                    f"applicability gate: class '{match}' not applicable"
                )
                finding.metadata["gate_class"] = match

    async def _run_adjudication(self) -> dict[str, int]:
        """Run deduplication and adjudication on findings (P14-03).

        Returns:
            Summary dict with adjudication statistics
        """
        from src.layers.l3_analysis.models import Finding

        # Collect all findings from all engines
        all_findings: list[Finding] = []
        for engine_name, scan_result in self.scan_results.items():
            all_findings.extend(scan_result.findings)

        # Phase 20 P-A2: mark gate-not-applicable findings before partition.
        # This runs lazily once more here so suppression also works when
        # _build_engine_options never ran (e.g. resume skipped engines).
        self._evaluate_applicability_gate()
        self._apply_gate_suppression(all_findings)

        # P3: keep agent low-confidence suspicious entries out of the
        # reportable set (kept in self._suspicious_review_queue for review).
        main_findings, review_findings = self._split_review_queue(all_findings)
        if review_findings:
            suspicious = [f for f in review_findings if (f.metadata or {}).get("is_suspicious")]
            gated = [f for f in review_findings if (f.metadata or {}).get("gate_suppressed")]
            self._suspicious_review_queue = [f.to_dict() for f in suspicious]
            self._gated_review_queue = [f.to_dict() for f in gated]
            if suspicious:
                logger.info(
                    f"P3: moved {len(suspicious)} is_suspicious entries "
                    f"to review queue (config include_suspicious_findings="
                    f"{self.config.get('include_suspicious_findings', False)})"
                )
            if gated:
                logger.info(
                    f"P-A2: moved {len(gated)} gate-not-applicable findings "
                    f"to review queue (config include_gated_findings="
                    f"{self.config.get('include_gated_findings', False)})"
                )
        all_findings = main_findings

        if not all_findings:
            logger.info("No findings to adjudicate")
            return {
                "total_findings": 0,
                "unique_findings": 0,
                "duplicates_removed": 0,
            }

        logger.info(f"Adjudicating {len(all_findings)} findings")

        # A4: assign the unified final score BEFORE adjudication. The four
        # rounds (D5) already synced finding.confidence/exploitability; this
        # turns them into the single comparable score that ClusterBased-
        # Deduplicator's "keep highest" logic and downstream reporting
        # actually read. Without it every comparison saw None → arbitrary
        # survivors.
        from src.core.final_score import assign_scores_to_findings

        all_findings = assign_scores_to_findings(all_findings)

        # Create adjudication service
        adjudication_service = create_adjudication_service(
            enable_deduplication=True,
            enable_adjudication=True,
            cluster_distance_threshold=0.3,
            llm_client=self.llm_client,
        )

        # Run adjudication
        adjudicated_findings, summary = await adjudication_service.adjudicate_findings_batch(
            findings=all_findings,
        )

        # Update scan_results with adjudicated findings
        # We need to rebuild the scan_results with unique findings
        self.scan_results = {}
        for finding in adjudicated_findings:
            # Get the engine from metadata
            engine = finding.metadata.get("engine", "unknown") if finding.metadata else "unknown"
            if engine not in self.scan_results:
                self.scan_results[engine] = ScanResult(
                    engine=engine,
                    findings=[],
                    status="completed",
                    source_path=str(self.source_path),  # Add required source_path
                )
            self.scan_results[engine].findings.append(finding)

            # Broadcast per-finding adjudication result
            adj_data = finding.metadata.get("adjudication", {}) if finding.metadata else {}
            await self.progress_callback.broadcast_event("adjudication_result", {
                "finding_id": finding.id or "unknown",
                "finding_title": getattr(finding, 'title', '') or '',
                "vuln_type": str(getattr(finding, 'rule_id', '') or ''),
                "severity": str(getattr(finding, 'severity', '') or ''),
                "file_path": getattr(finding.location, 'file', '') if hasattr(finding, 'location') and finding.location else '',
                "final_status": adj_data.get("final_status", ""),
                "override_applied": adj_data.get("override_applied", False),
                "override_reason": adj_data.get("override_reason", ""),
                "evidence_strength": adj_data.get("evidence_strength"),
                "report_status": adj_data.get("report_status", ""),
            })

        # Store summary for later use in database
        self.adjudication_summary = summary.to_dict()

        logger.info(
            f"Adjudication complete: {summary.total_findings} total, "
            f"{summary.unique_findings} unique, "
            f"{summary.duplicates_removed} duplicates removed"
        )

        return {
            "total_findings": summary.total_findings,
            "unique_findings": summary.unique_findings,
            "duplicates_removed": summary.duplicates_removed,
        }

    async def _run_adversarial_verification(self) -> dict[str, int]:
        """Run adversarial verification on findings (P14-04).

        Returns:
            Summary dict with verification statistics
        """
        from src.layers.l3_analysis.models import Finding

        # Check if LLM client is available
        if not self.llm_client:
            logger.warning("Adversarial verification disabled: no LLM client")
            return {"verified_count": 0, "confirmed": 0, "rejected": 0}

        # Collect all findings from all engines
        all_findings: list[Finding] = []
        for engine_name, scan_result in self.scan_results.items():
            logger.info(f"Adversarial: {engine_name} has {len(scan_result.findings)} findings")
            all_findings.extend(scan_result.findings)

        if not all_findings:
            logger.info("No findings to verify adversarially")
            return {"verified_count": 0, "confirmed": 0, "rejected": 0}

        logger.info(f"Adversarial: collected {len(all_findings)} findings for verification")

        # Get adversarial configuration
        adversarial_config = self.config.get("adversarial", False)
        max_rounds = self.config.get("adversarial_max_rounds", 5)
        round_timeout = self.config.get("adversarial_round_timeout", 600)

        if not adversarial_config:
            logger.info("Adversarial verification disabled by config")
            return {"verified_count": 0, "confirmed": 0, "rejected": 0}

        logger.info(f"Starting adversarial verification for {len(all_findings)} findings")

        # Create adversarial service from database (verification type config)
        # P18-Bugfix: 传递现有的 llm_client 以正确统计 token
        adversarial_service = await create_adversarial_service_from_db(
            db_session_factory=self.db_session_factory,
            max_rounds=max_rounds,
            round_timeout=round_timeout,
            progress_callback=self._adversarial_progress_callback,
            llm_client=self.llm_client,  # 复用 orchestrator 的 llm_client
        )

        if adversarial_service is None:
            logger.warning("No verification LLM config found, skipping adversarial verification")
            return {"verified_count": 0, "confirmed": 0, "rejected": 0, "skipped": True}

        # Phase 18/P6: filter findings via the verification gatekeeper,
        # replacing the hand-written severity/confidence filter. The
        # gatekeeper auto-confirms dataflow-backed EXPLOITABLE / PoC-backed
        # findings, auto-rejects clear false positives, and skips low-value
        # ones — saving ~40% of adversarial LLM calls. The adversarial
        # service itself is still used below for findings that pass the gate.
        from src.layers.l3_analysis.verification.verification_gatekeeper import (
            should_verify_finding,
        )

        gate_decisions = [(f, should_verify_finding(f)) for f in all_findings]
        findings_to_verify = [f for f, (verify, _) in gate_decisions if verify]

        # Broadcast skipped findings with the gatekeeper's reason.
        for f, (verify, reason) in gate_decisions:
            if verify:
                continue
            await self.progress_callback.broadcast_event("finding_skipped", {
                "finding_id": f.id or "unknown",
                "finding_title": getattr(f, 'title', '') or '',
                "severity": str(getattr(f, 'severity', '')),
                "reason": reason,
            })

        if not findings_to_verify:
            logger.info("No findings met criteria for adversarial verification")
            return {"verified_count": 0, "confirmed": 0, "rejected": 0}

        logger.info(f"Verifying {len(findings_to_verify)} findings adversarially (filtered from {len(all_findings)})")

        # Track token usage before adversarial verification
        tokens_before = 0
        if self.llm_client:
            tokens_before = self.llm_client.get_total_usage().total_tokens

        # Verify findings in batch
        # P18: Use concurrency manager with config from database
        from src.core.llm import get_verification_concurrency_manager_from_db
        verification_manager = await get_verification_concurrency_manager_from_db(self.db_session_factory)

        # Adversarial verification spawns multiple LLM calls per finding
        # (attacker + defender can run in parallel, then arbiter).
        # Divide the DB's max_concurrent by the inner parallelism so the
        # actual concurrent LLM requests stay within the intended limit.
        inner_llm_parallelism = 2  # attacker + defender run concurrently
        finding_concurrency = max(
            1,
            verification_manager.current_concurrent // inner_llm_parallelism,
        )
        logger.info(
            f"Adversarial finding-level concurrency: {finding_concurrency} "
            f"(DB max_concurrent={verification_manager.current_concurrent} / {inner_llm_parallelism})"
        )
        # Pass concurrency_manager so adversarial service uses adaptive semaphore
        adversarial_service._concurrency_manager = verification_manager

        # Set total for fine-grained progress tracking
        self._adversarial_total = len(findings_to_verify)
        self._adversarial_done = 0

        await self.progress_callback.on_progress(
            0, "开始对抗性验证...", phase_name="adversarial_verification"
        )

        verification_results = await adversarial_service.verify_findings_batch(
            findings=findings_to_verify,
            source_path=self.source_path,
            max_concurrent=finding_concurrency,
        )

        # Track token usage after adversarial verification
        tokens_after = 0
        if self.llm_client:
            tokens_after = self.llm_client.get_total_usage().total_tokens
            self._adversarial_tokens_used = max(0, tokens_after - tokens_before)
            logger.info(f"Adversarial verification used {self._adversarial_tokens_used} tokens")

        # Apply results to findings
        confirmed = 0
        rejected = 0
        logger.info(f"Adversarial results: {len(verification_results)} entries, "
                     f"all_findings IDs: {[f.id for f in all_findings]}, "
                     f"result keys: {list(verification_results.keys())}")
        for finding_id, result in verification_results.items():
            status_val = result.get("status", "UNKNOWN")
            logger.info(f"Adversarial result: finding_id={finding_id}, status={status_val}, "
                         f"status_type={type(status_val)}, verdict={result.get('verdict')}")
            # Find the finding
            found = False
            for finding in all_findings:
                if finding.id == finding_id:
                    # Store result in finding metadata
                    finding.metadata = finding.metadata or {}
                    finding.metadata["adversarial_verification"] = result

                    found = True
                    # Update counters
                    if result.get("status") == "confirmed":
                        confirmed += 1
                    elif result.get("status") == "rejected":
                        rejected += 1

                    logger.info(
                        f"Finding {finding_id}: matched, status={result.get('status')} "
                        f"(confidence: {result.get('confidence', 0):.2f}), "
                        f"confirmed={confirmed}, rejected={rejected}"
                    )
                    break
            if not found:
                logger.warning(f"Finding {finding_id} not found in all_findings (IDs: {[f.id for f in all_findings[:5]]})")

        summary = {
            "verified_count": len(verification_results),
            "confirmed": confirmed,
            "rejected": rejected,
            "uncertain": len(verification_results) - confirmed - rejected,
        }

        logger.info(
            f"Adversarial verification complete: {summary['verified_count']} verified, "
            f"{summary['confirmed']} confirmed, {summary['rejected']} rejected"
        )

        return summary

    def _adversarial_progress_callback(
        self,
        event_type: str,
        data: dict[str, Any],
    ) -> None:
        """Progress callback for adversarial verification events.

        Args:
            event_type: Type of event (e.g., "adversarial_round")
            data: Event data
        """
        try:
            # Track finding-level progress for fine-grained progress bar
            if event_type == "finding_verified" and hasattr(self, "_adversarial_total"):
                self._adversarial_done = getattr(self, "_adversarial_done", 0) + 1
                total = max(self._adversarial_total, 1)
                pct = int(self._adversarial_done / total * 100)
                # Schedule progress update (fire-and-forget)
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(
                        self.progress_callback.on_progress(
                            pct,
                            f"对抗性验证 {self._adversarial_done}/{total}",
                            phase_name="adversarial_verification",
                        )
                    )
                except Exception:
                    pass

            if hasattr(self.progress_callback, "broadcast_event"):
                # Schedule the async broadcast in the running event loop
                loop = asyncio.get_running_loop()
                loop.create_task(
                    self.progress_callback.broadcast_event(
                        event_type=event_type,
                        data=data,
                    )
                )
                logger.debug(f"Adversarial callback scheduled: {event_type} round={data.get('round')}")
            else:
                logger.warning(f"progress_callback has no broadcast_event method: {type(self.progress_callback)}")
        except RuntimeError:
            # No running event loop — try to get the Celery event loop
            logger.warning("No running event loop for adversarial callback, trying direct call")
            try:
                asyncio.get_event_loop().run_until_complete(
                    self.progress_callback.broadcast_event(event_type=event_type, data=data)
                )
            except Exception as e2:
                logger.warning(f"Adversarial callback fallback also failed: {e2}")
        except Exception as e:
            logger.warning(f"Failed to broadcast adversarial progress: {e}")

    async def _finalize_results(self) -> None:
        """
        Merge results from all engines and save to database.

        Implements:
        - Result merging and deduplication
        - Finding database insertion
        - Statistics update
        """
        all_findings = []

        # Collect findings from all engines
        for engine_name, scan_result in self.scan_results.items():
            logger.info(
                f"Scan {self.scan_id}: {engine_name} found "
                f"{len(scan_result.findings)} findings"
            )

            for finding in scan_result.findings:
                # Mark source engine
                if not finding.metadata:
                    finding.metadata = {}
                finding.metadata["source_engine"] = engine_name
                all_findings.append(finding)

        # Semantic cross-finding deduplication happened earlier in
        # _run_adjudication(); this block only guards persistence. A resumed
        # scan re-runs _finalize_results, so we must not re-insert findings
        # already stored for this scan, and we dedup within this batch too.
        # Key: (vuln_type, file_path, line_start) — matches how FindingModel is
        # populated below (vuln_type = rule_id or type).
        async with self.db_session_factory() as db:
            existing_keys: set[tuple] = set()
            existing_stmt = select(
                FindingModel.vuln_type,
                FindingModel.file_path,
                FindingModel.line_start,
            ).where(FindingModel.scan_id == self.scan_id)
            for row in (await db.execute(existing_stmt)).all():
                existing_keys.add((row[0], row[1], row[2]))

            saved_count = 0
            skipped_duplicates = 0
            for finding_data in all_findings:
                key = (
                    finding_data.rule_id or finding_data.type.value,
                    finding_data.location.file,
                    finding_data.location.line,
                )
                if key in existing_keys:
                    skipped_duplicates += 1
                    continue
                existing_keys.add(key)

                # Derive finding status from adversarial verification and adjudication
                finding_status = self._derive_finding_status(finding_data)

                finding = FindingModel(
                    scan_id=self.scan_id,
                    vuln_type=finding_data.rule_id or finding_data.type.value,
                    severity=finding_data.severity.value,
                    confidence=finding_data.confidence,
                    file_path=finding_data.location.file,
                    line_start=finding_data.location.line,
                    line_end=finding_data.location.end_line,
                    function_name=finding_data.location.function,
                    title=finding_data.title,
                    description=finding_data.description,
                    evidence=finding_data.location.snippet,
                    remediation=finding_data.fix_suggestion,
                    engine=finding_data.source,
                    status=finding_status,
                    extra_metadata=finding_data.metadata,
                )
                db.add(finding)
                saved_count += 1

            await db.commit()

            if skipped_duplicates:
                logger.info(
                    f"Scan {self.scan_id}: Skipped {skipped_duplicates} duplicate "
                    f"findings on save (resume-safe)"
                )

        # Unique findings for this scan (already-persisted + newly saved).
        self.total_findings = len(existing_keys)
        logger.info(
            f"Scan {self.scan_id}: Saved {saved_count} findings to database "
            f"({self.total_findings} total unique)"
        )

    def _derive_finding_status(self, finding_data: Finding) -> str:
        """Derive finding status from adversarial verification and adjudication metadata.

        Priority: adversarial verification > adjudication > default pending

        Args:
            finding_data: Finding object with metadata containing verification results

        Returns:
            Status string: confirmed, false_positive, conditional, or pending
        """
        metadata = finding_data.metadata or {}

        # 1. Check adversarial verification result (highest priority)
        adversarial = metadata.get("adversarial_verification")
        if adversarial and isinstance(adversarial, dict):
            adv_status = adversarial.get("status", "")
            # Map adversarial status to finding status
            status_map = {
                "confirmed": "confirmed",
                "rejected": "false_positive",
                "uncertain": "conditional",
                "timeout": "conditional",
            }
            mapped = status_map.get(adv_status)
            if mapped:
                logger.debug(
                    f"Finding {finding_data.id}: status={mapped} from adversarial ({adv_status})"
                )
                return mapped

        # 2. Check adjudication result
        adjudication = metadata.get("adjudication")
        if adjudication and isinstance(adjudication, dict):
            adj_status = adjudication.get("final_status", "")
            status_map = {
                "confirmed": "confirmed",
                "false_positive": "false_positive",
                "conditional": "conditional",
                "not_exploitable": "false_positive",
                "informational": "conditional",
            }
            mapped = status_map.get(adj_status)
            if mapped:
                logger.debug(
                    f"Finding {finding_data.id}: status={mapped} from adjudication ({adj_status})"
                )
                return mapped

        # 3. Default pending
        return "pending"

    # ========================================================================
    # Resource Cleanup
    # ========================================================================

    async def _cleanup(self) -> None:
        """Clean up temporary resources."""
        if self.temp_dir and self.temp_dir.exists():
            try:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
                logger.info(f"Scan {self.scan_id}: Cleaned up {self.temp_dir}")
            except Exception as e:
                logger.warning(f"Scan {self.scan_id}: Cleanup failed: {e}")
            finally:
                self.temp_dir = None

    # ========================================================================
    # Phase 0: L1_Preparation (P14-01)
    # ========================================================================

    async def _run_l1_preparation(self) -> None:
        """
        Run L1_Preparation phase (Phase 0).

        P14-01: 集成 AttackSurfaceDetection
        - TechStackDetection (已有)
        - AttackSurfaceDetection (新增)

        This phase runs before source preparation to gather intelligence
        about the project's attack surface, which can be used to optimize
        downstream scanning phases.
        """
        source_path = Path(self.source_path)

        # Handle Git URL — clone repository first
        if self.source_type == "git" or (
            isinstance(self.source_path, str)
            and self.source_path.startswith(("http://", "https://", "git@", "ssh://"))
        ):
            self.temp_dir = Path(
                tempfile.mkdtemp(prefix=f"deepvuln_git_{self.scan_id}_")
            )
            try:
                import subprocess

                git_url = str(self.source_path)
                # Auto-expand owner/repo short format to full GitHub URL
                if not git_url.startswith(("http://", "https://", "git@", "ssh://")):
                    import re
                    if re.match(r"^[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+$", git_url):
                        git_url = f"https://github.com/{git_url}.git"
                        logger.info(f"Phase 0: Expanded short repo to {git_url}")
                # Support branch option
                branch = self.config.get("branch")
                clone_cmd = ["git", "clone", "--depth", "1"]
                if branch:
                    clone_cmd.extend(["--branch", branch])
                clone_cmd.extend([git_url, str(self.temp_dir)])

                logger.info(f"Phase 0: Cloning Git repo: {git_url} -> {self.temp_dir}")
                result = subprocess.run(
                    clone_cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if result.returncode != 0:
                    raise ValueError(
                        f"git clone failed (exit {result.returncode}): {result.stderr.strip()}"
                    )
                self.source_path = self.temp_dir
                logger.info(f"Phase 0: Git clone complete: {self.source_path}")
            except subprocess.TimeoutExpired:
                if self.temp_dir and self.temp_dir.exists():
                    shutil.rmtree(self.temp_dir, ignore_errors=True)
                    self.temp_dir = None
                raise ValueError(f"git clone timed out after 300s for {self.source_path}")
            except ValueError:
                if self.temp_dir and self.temp_dir.exists():
                    shutil.rmtree(self.temp_dir, ignore_errors=True)
                    self.temp_dir = None
                raise
            except Exception as e:
                if self.temp_dir and self.temp_dir.exists():
                    shutil.rmtree(self.temp_dir, ignore_errors=True)
                    self.temp_dir = None
                raise ValueError(f"Failed to clone Git repository: {e}")

        # Handle ZIP files for path resolution
        elif source_path.suffix == ".zip":
            # Extract ZIP for Phase 0 analysis (tech stack + attack surface)
            # The extracted directory will be reused in Phase 1 to avoid double extraction
            self.temp_dir = Path(
                tempfile.mkdtemp(prefix=f"deepvuln_l1_{self.scan_id}_")
            )
            try:
                logger.info(f"Phase 0: Extracting ZIP: {source_path} -> {self.temp_dir}")
                safe_unpack_archive(source_path, self.temp_dir)
                self.source_path = self._find_code_directory(self.temp_dir)
                logger.info(f"Phase 0: Using code directory: {self.source_path}")
            except Exception as e:
                if self.temp_dir and self.temp_dir.exists():
                    shutil.rmtree(self.temp_dir, ignore_errors=True)
                    self.temp_dir = None
                raise ValueError(f"Failed to extract ZIP for L1 analysis: {e}")
        else:
            self.source_path = source_path

        # Step 1: TechStackDetection
        logger.info(f"Scan {self.scan_id}: Running TechStackDetection")
        self.tech_stack = await self._detect_tech_stack_for_l1()

        # Step 2: AttackSurfaceDetection (if enabled and LLM client available)
        self.attack_surface_report = None

        # Check if attack surface detection is enabled
        llm_detect = self.config.get("llm_detect", False)
        static_only = self.config.get("static_only", False)

        if not static_only and self._get_attack_surface_service():
            try:
                logger.info(f"Scan {self.scan_id}: Running AttackSurfaceDetection")

                # Determine detection mode
                if llm_detect:
                    detection_mode = DetectionMode.PARALLEL
                else:
                    detection_mode = DetectionMode.STATIC

                config = AttackSurfaceDetectionConfig(
                    mode=detection_mode,
                    static_only=static_only,
                )

                service = self._get_attack_surface_service()
                frameworks = self.tech_stack.get("frameworks", [])

                report = await service.detect(self.source_path, config, frameworks)

                # Store original report object for verification service
                self.attack_surface_report_obj = report

                # Store finding context for downstream use
                self.attack_surface_report = service.create_finding_context(report)

                logger.info(
                    f"Scan {self.scan_id}: AttackSurfaceDetection complete - "
                    f"{self.attack_surface_report['attack_surface']['total_entry_points']} entry points"
                )

            except Exception as e:
                logger.warning(f"Scan {self.scan_id}: AttackSurfaceDetection failed: {e}")
                await self.progress_callback.on_warning(
                    f"AttackSurfaceDetection failed: {e}"
                )

        # NOTE: Don't clean up temp_dir here - it will be reused by Phase 1
        # The temp_dir will be cleaned up at the end of the scan in _cleanup()

    async def _detect_tech_stack_for_l1(self) -> Dict[str, Any]:
        """
        Detect tech stack for L1_Preparation phase.

        This is a wrapper around _detect_tech_stack that handles the case
        where source_path hasn't been set yet.
        """
        # Reuse existing tech stack detection logic
        return await self._detect_tech_stack_impl()

    async def _detect_tech_stack_impl(self) -> Dict[str, Any]:
        """
        Implementation of tech stack detection.

        Extracted from _detect_tech_stack for reuse in L1 phase.
        """
        detector = TechStackDetector()
        tech_stack = detector.detect(self.source_path)

        # Convert to simplified format
        languages = [
            lang.language.value
            for lang in tech_stack.languages
        ]

        frameworks = [
            framework.name for framework in tech_stack.frameworks
        ]

        file_counts = {}
        for lang_info in tech_stack.languages:
            file_counts[lang_info.language.value] = lang_info.file_count

        return {
            "languages": languages,
            "primary_language": tech_stack.primary_language,
            "secondary_languages": tech_stack.secondary_languages or [],
            "frameworks": frameworks,
            "file_counts": file_counts,
            "total_loc": tech_stack.total_loc,
            "total_files": tech_stack.total_files,
            "project_type": tech_stack.project_type.value if tech_stack.project_type else "unknown",
            "has_tests": tech_stack.has_tests,
            "has_docs": tech_stack.has_docs,
            "is_monorepo": tech_stack.is_monorepo,
            "databases": [db.name for db in tech_stack.databases],
            "middleware": [mw.name for mw in tech_stack.middleware],
            "package_managers": tech_stack.package_managers,
            "build_tools": tech_stack.build_tools,
            "ci_cd": tech_stack.ci_cd,
            "_full_stack": tech_stack,
        }

    async def _update_token_statistics(self) -> Dict[str, Any]:
        """Update token usage statistics (P14-05).

        This method should be called during Phase 6 (Result_Finalization)
        to collect and store token usage information.

        Returns:
            Dictionary with token usage statistics
        """
        token_stats = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "agent_scan_tokens": 0,  # P14-05: Agent 扫描词元
            "adversarial_tokens": 0,  # P14-05: LLM 辩论词元
            "estimated_cost": 0.0,
        }

        logger.info(f"Token statistics check: llm_client={self.llm_client is not None}")

        # Collect tokens from orchestrator's LLM client
        if self.llm_client is not None:
            usage = self.llm_client.get_total_usage()
            logger.info(f"LLM client total tokens: {usage.total_tokens}")
            token_stats["prompt_tokens"] = usage.prompt_tokens
            token_stats["completion_tokens"] = usage.completion_tokens
            token_stats["total_tokens"] = usage.total_tokens

        # Collect tokens from engine raw_output (e.g., agent engine)
        # These are Agent 扫描词元
        agent_scan_tokens = 0
        for engine_name, scan_result in self.scan_results.items():
            if scan_result.raw_output and isinstance(scan_result.raw_output, dict):
                engine_tokens = scan_result.raw_output.get("total_tokens", 0)
                if engine_tokens:
                    logger.info(f"Engine {engine_name} tokens: {engine_tokens}")
                    agent_scan_tokens += engine_tokens

        # Use tracked adversarial tokens if available
        adversarial_tokens = self._adversarial_tokens_used

        # If we have engine tokens, use them; otherwise calculate
        if agent_scan_tokens > 0:
            token_stats["agent_scan_tokens"] = agent_scan_tokens
        else:
            # Fallback: total - adversarial = agent scan
            token_stats["agent_scan_tokens"] = max(
                0, token_stats["total_tokens"] - adversarial_tokens
            )

        # Use tracked adversarial tokens
        token_stats["adversarial_tokens"] = adversarial_tokens

        # Calculate estimated cost (using simple rate: $0.002 per 1K tokens)
        token_stats["estimated_cost"] = round(
            token_stats["total_tokens"] * 0.002 / 1000, 4
        )

        logger.info(f"Total token statistics: {token_stats}")

        # Update scan record with token usage
        if token_stats["total_tokens"] > 0:
            async with self.db_session_factory() as db:
                from src.web.repositories.scan import ScanRepository

                scan_repo = ScanRepository()
                scan = await scan_repo.get(db, id=self.scan_id)
                if scan:
                    # Update simple tokens_used field and token_usage JSON
                    logger.info(f"Scan {self.scan_id}: Updating token_usage: agent_scan_tokens={token_stats['agent_scan_tokens']}, adversarial_tokens={token_stats['adversarial_tokens']}")
                    await scan_repo.update(db, db_obj=scan, obj_in={
                        "tokens_used": token_stats["total_tokens"],
                        "token_usage": {
                            "prompt_tokens": token_stats["prompt_tokens"],
                            "completion_tokens": token_stats["completion_tokens"],
                            "total_tokens": token_stats["total_tokens"],
                            "agent_scan_tokens": token_stats["agent_scan_tokens"],
                            "adversarial_tokens": token_stats["adversarial_tokens"],
                            "estimated_cost": token_stats["estimated_cost"],
                        },
                    })
                    # Ensure the update is committed immediately
                    await db.commit()
                    logger.info(f"Scan {self.scan_id}: token_usage updated and committed")
                else:
                    logger.warning(f"Scan {self.scan_id}: Not found in database, cannot update token_usage")

        return token_stats


# ============================================================================
# Factory Function
# ============================================================================


def create_scan_orchestrator(
    scan_id: int,
    scan_config: Dict[str, Any],
    progress_callback: Optional[ProgressCallback] = None,
    llm_client: Optional[LLMClient] = None,
    source_type: Optional[str] = None,
) -> ScanOrchestrator:
    """
    Factory function to create a ScanOrchestrator instance.

    Args:
        scan_id: ID of the scan
        scan_config: Scan configuration
        progress_callback: Optional progress callback
        llm_client: Optional LLM client for LLM-based features
        source_type: Type of source ("local", "git", "zip")

    Returns:
        Configured ScanOrchestrator instance
    """
    return ScanOrchestrator(
        scan_id=scan_id,
        scan_config=scan_config,
        progress_callback=progress_callback,
        llm_client=llm_client,
        source_type=source_type,
    )
