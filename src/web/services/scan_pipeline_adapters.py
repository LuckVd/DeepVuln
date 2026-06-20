"""Web adapters bridging ScanPipeline's protocols to ScanOrchestrator.

``WebProgressSink`` maps pipeline phase events onto the orchestrator's existing
``ProgressCallback`` (preserving the frontend event schema), and
``WebCheckpointSink`` delegates to the orchestrator's checkpoint helpers
(preserving resume semantics). This lets ``execute_scan`` drive a ScanPipeline
without changing progress/checkpoint behaviour.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.web.services.progress_broadcaster import ProgressCallback
    from src.web.services.scan_orchestrator import ScanOrchestrator


class WebProgressSink:
    """Adapt ScanPipeline phase events to the orchestrator's ProgressCallback.

    The pipeline calls ``on_phase_complete(phase, **summary)``; ProgressCallback
    expects ``on_phase_complete(phase, result_dict)``. Skipped / failed /
    intra-phase events are no-ops to preserve prior behaviour: conditional
    phases were simply not entered, and failures surface via the orchestrator's
    own ``on_scan_failed`` in its outer try/except.
    """

    def __init__(self, callback: ProgressCallback) -> None:
        self._cb = callback

    async def on_phase_start(self, phase: str, **data: Any) -> None:
        await self._cb.on_phase_start(phase, **data)

    async def on_phase_progress(
        self, phase: str, current: int, total: int, **extra: Any
    ) -> None:
        # Engines report progress via on_finding / on_engine_*, not this channel.
        return

    async def on_phase_complete(self, phase: str, **data: Any) -> None:
        # Re-pack the summary kwargs into the positional result dict the
        # ProgressCallback contract expects.
        await self._cb.on_phase_complete(phase, data)

    async def on_phase_skipped(self, phase: str) -> None:
        # Prior behaviour emitted nothing for skipped (conditional) phases.
        return

    async def on_phase_failed(self, phase: str, error: str) -> None:
        # The orchestrator's outer try/except emits on_scan_failed.
        return

    async def on_scan_complete(self, **summary: Any) -> None:
        # Invoked directly by execute_scan (the pipeline does not call this).
        return

    async def on_scan_failed(self, error: str) -> None:
        # Invoked directly by execute_scan (the pipeline does not call this).
        return


class WebCheckpointSink:
    """Adapt ScanPipeline checkpoint calls to ScanOrchestrator's helpers.

    ``skip_phases`` is seeded from the orchestrator's resume bookkeeping
    (``_completed_phases``, loaded from a prior checkpoint at scan start).
    """

    def __init__(self, orchestrator: ScanOrchestrator) -> None:
        self._orch = orchestrator

    @property
    def skip_phases(self) -> list[str]:
        return list(getattr(self._orch, "_completed_phases", set()))

    async def save(self, phase: str, data: dict[str, Any] | None = None) -> None:
        # D3: snapshot the current findings into resume_data so a resumed scan
        # can skip completed phases without losing their output. This lives
        # under resume_data (not the progress summary) so findings never leak
        # into the frontend progress event built from ``data``.
        # P7-C6: resume_data now also carries completed_engines (single source
        # of truth via _serialize_resume_data, shared with mid-phase engine
        # saves).
        payload = dict(data or {})
        payload["resume_data"] = self._orch._serialize_resume_data()
        await self._orch._save_checkpoint_phase(phase, payload)

    async def clean(self) -> None:
        await self._orch._clean_checkpoint()
