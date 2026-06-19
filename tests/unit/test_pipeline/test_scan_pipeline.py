"""Unit tests for the shared ScanPipeline.

These tests are dependency-free (the pipeline module uses only the stdlib), so
they validate orchestration / skip / resume / checkpoint behavior in isolation.
"""

from pathlib import Path

import pytest

from src.layers.pipeline import PhaseSpec, ScanContext, ScanPhase, ScanPipeline


class FakeProgress:
    def __init__(self) -> None:
        self.events: list[tuple] = []

    async def on_phase_start(self, phase: str, **data) -> None:
        self.events.append(("start", phase))

    async def on_phase_progress(self, phase: str, current: int, total: int, **extra) -> None:
        self.events.append(("progress", phase, current, total))

    async def on_phase_complete(self, phase: str, **data) -> None:
        self.events.append(("complete", phase))

    async def on_phase_skipped(self, phase: str) -> None:
        self.events.append(("skipped", phase))

    async def on_phase_failed(self, phase: str, error: str) -> None:
        self.events.append(("failed", phase, error))

    async def on_scan_complete(self, **summary) -> None:
        self.events.append(("scan_complete",))

    async def on_scan_failed(self, error: str) -> None:
        self.events.append(("scan_failed", error))


class FakeCheckpoint:
    def __init__(self, skip_phases: list[str] | None = None) -> None:
        self.skip_phases = skip_phases or []
        self.saved: list[str] = []
        self.cleaned = False

    async def save(self, phase: str, data: dict | None = None) -> None:
        self.saved.append(phase)

    async def clean(self) -> None:
        self.cleaned = True


def _ctx() -> ScanContext:
    return ScanContext(scan_id="t1", source_path=Path("/tmp"))


@pytest.mark.asyncio
async def test_basic_execution_runs_all_phases_in_order() -> None:
    progress = FakeProgress()
    ran: list[str] = []

    async def r1(ctx, pipeline):
        ran.append("a")

    async def r2(ctx, pipeline):
        ran.append("b")

    phases = [
        PhaseSpec(ScanPhase.L1_PREPARATION, r1, checkpoint_key="a"),
        PhaseSpec(ScanPhase.ENGINE_EXECUTION, r2),
    ]
    await ScanPipeline(_ctx(), phases, progress).execute()
    assert ran == ["a", "b"]
    assert ("start", "l1_preparation") in progress.events
    assert ("complete", "engine_execution") in progress.events


@pytest.mark.asyncio
async def test_skip_when_skips_phase() -> None:
    progress = FakeProgress()
    ran: list[str] = []

    async def r1(ctx, pipeline):
        ran.append("a")

    async def r2(ctx, pipeline):
        ran.append("b")

    phases = [
        PhaseSpec(ScanPhase.L1_PREPARATION, r1),
        PhaseSpec(ScanPhase.ENGINE_EXECUTION, r2, skip_when=lambda c: True),
    ]
    await ScanPipeline(_ctx(), phases, progress).execute()
    assert ran == ["a"]
    assert ("skipped", "engine_execution") in progress.events


@pytest.mark.asyncio
async def test_checkpoint_resume_skips_completed_phases() -> None:
    progress = FakeProgress()
    ran: list[str] = []

    async def r1(ctx, pipeline):
        ran.append("a")

    async def r2(ctx, pipeline):
        ran.append("b")

    ckpt = FakeCheckpoint(skip_phases=["l1_preparation"])
    phases = [
        PhaseSpec(ScanPhase.L1_PREPARATION, r1, checkpoint_key="a"),
        PhaseSpec(ScanPhase.ENGINE_EXECUTION, r2, checkpoint_key="b"),
    ]
    await ScanPipeline(_ctx(), phases, progress, checkpoint=ckpt).execute()
    assert ran == ["b"]  # phase a was skipped (already completed)
    assert "l1_preparation" not in ckpt.saved


@pytest.mark.asyncio
async def test_resume_from_skips_preceding_phases() -> None:
    progress = FakeProgress()
    ran: list[str] = []

    async def r1(ctx, pipeline):
        ran.append("a")

    async def r2(ctx, pipeline):
        ran.append("b")

    phases = [PhaseSpec(ScanPhase.L1_PREPARATION, r1), PhaseSpec(ScanPhase.ENGINE_EXECUTION, r2)]
    await ScanPipeline(_ctx(), phases, progress).execute(resume_from="engine_execution")
    assert ran == ["b"]


@pytest.mark.asyncio
async def test_failure_keeps_checkpoint_for_next_resume() -> None:
    progress = FakeProgress()

    async def boom(ctx, pipeline):
        raise RuntimeError("x")

    ckpt = FakeCheckpoint()
    phases = [PhaseSpec(ScanPhase.L1_PREPARATION, boom, checkpoint_key="a")]
    with pytest.raises(RuntimeError):
        await ScanPipeline(_ctx(), phases, progress, checkpoint=ckpt).execute()
    assert not ckpt.cleaned  # checkpoint preserved so the next attempt can resume


@pytest.mark.asyncio
async def test_success_cleans_checkpoint() -> None:
    progress = FakeProgress()

    async def ok(ctx, pipeline):
        pass

    ckpt = FakeCheckpoint()
    phases = [PhaseSpec(ScanPhase.L1_PREPARATION, ok, checkpoint_key="a")]
    await ScanPipeline(_ctx(), phases, progress, checkpoint=ckpt).execute()
    assert ckpt.cleaned
