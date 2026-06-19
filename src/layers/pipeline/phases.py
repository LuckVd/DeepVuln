"""Scan pipeline phase definitions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Awaitable, Callable

if TYPE_CHECKING:
    from src.layers.pipeline.context import ScanContext
    from src.layers.pipeline.scan_pipeline import ScanPipeline


class ScanPhase(str, Enum):
    """Canonical scan phases.

    Values intentionally match the Web progress event names
    (``on_phase_start("l1_preparation")`` etc.) so no schema migration is
    needed when the pipeline drives progress.
    """

    L1_PREPARATION = "l1_preparation"
    SOURCE_PREPARATION = "source_preparation"
    ENGINE_SELECTION = "engine_selection"
    ENGINE_EXECUTION = "engine_execution"
    # Multi-round exploitability adjudication (rounds 1-4). Supersedes the old
    # standalone "exploitability_verification" phase.
    ROUNDS_AUDIT = "rounds_audit"
    ADJUDICATION = "deduplication_adjudication"
    ADVERSARIAL = "adversarial_verification"
    RESULT_MERGE = "result_merging"
    TOKEN_STATS = "token_statistics"


# A phase runner receives the shared context and the running pipeline (so it can
# report sub-progress via ``pipeline.report_progress``).
PhaseRunner = Callable[["ScanContext", "ScanPipeline"], Awaitable[None]]


@dataclass
class PhaseSpec:
    """Declarative description of one pipeline phase."""

    phase: ScanPhase
    runner: PhaseRunner
    # Return True to skip this phase (e.g. feature flag off, no LLM configured).
    skip_when: Callable[["ScanContext"], bool] | None = None
    # If set, the phase's summary is checkpointed after completion (enables resume).
    checkpoint_key: str | None = None
    # Builds the progress "complete" payload from context.
    summary: Callable[["ScanContext"], dict[str, Any]] | None = None
