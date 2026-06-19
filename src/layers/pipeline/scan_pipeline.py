"""ScanPipeline — ordered, resumable execution of scan phases.

The pipeline owns NO domain logic. Phases are async callbacks over a shared
``ScanContext``; CLI and Web inject the same phase runners and differ only in
their ``ProgressSink`` / ``CheckpointSink`` adapters. This is the single source
of scan orchestration intended to eliminate the former CLI/Web duplication.
"""

from __future__ import annotations

from typing import Any

from src.layers.pipeline.context import ScanContext
from src.layers.pipeline.phases import PhaseSpec
from src.layers.pipeline.progress import ProgressSink


class ScanPipeline:
    """Executes a list of :class:`PhaseSpec` in order.

    Resume semantics: phases listed in the checkpoint's ``skip_phases`` (loaded
    from a prior interrupted run), plus any phases strictly before an explicit
    ``resume_from``, are skipped. Each checkpointed phase is persisted after it
    completes; the checkpoint is cleaned only on full success (a failed run
    keeps its checkpoint so the next attempt can resume).
    """

    def __init__(
        self,
        ctx: ScanContext,
        phases: list[PhaseSpec],
        progress: ProgressSink,
        checkpoint: Any | None = None,
    ) -> None:
        self.ctx = ctx
        self._phases = phases
        self._progress = progress
        self._checkpoint = checkpoint
        self._explicit_skip: set[str] = set()

    def request_skip(self, phase: str) -> None:
        """Dynamically request a phase be skipped (e.g. a feature flag is off)."""
        self._explicit_skip.add(phase)

    async def execute(self, resume_from: str | None = None) -> ScanContext:
        skip = self._compute_skip(resume_from)
        for spec in self._phases:
            name = spec.phase.value
            if name in skip or (spec.skip_when and spec.skip_when(self.ctx)):
                await self._progress.on_phase_skipped(name)
                continue
            await self._progress.on_phase_start(name)
            try:
                await spec.runner(self.ctx, self)
            except Exception as e:  # noqa: BLE001 — surface to caller, keep checkpoint
                self.ctx.errors.append(f"{name}: {e}")
                await self._progress.on_phase_failed(name, str(e))
                raise
            summary = spec.summary(self.ctx) if spec.summary else {}
            await self._progress.on_phase_complete(name, **summary)
            if self._checkpoint and spec.checkpoint_key:
                await self._checkpoint.save(name, summary)
        # Full success → drop the checkpoint so the next scan starts fresh.
        if self._checkpoint:
            await self._checkpoint.clean()
        return self.ctx

    def _compute_skip(self, resume_from: str | None) -> set[str]:
        skip: set[str] = set(self._explicit_skip)
        if self._checkpoint:
            skip |= set(getattr(self._checkpoint, "skip_phases", []) or [])
        if resume_from:
            names = [p.phase.value for p in self._phases]
            if resume_from in names:
                skip.update(names[: names.index(resume_from)])
        return skip

    async def report_progress(
        self, phase: str, current: int, total: int, **extra: Any
    ) -> None:
        """Phase runners call this to report intra-phase progress."""
        await self._progress.on_phase_progress(phase, current, total, **extra)
