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
    # Exploitability verification (Round-4 / multi-round adjudication). The value
    # matches the live Web progress event name + frontend i18n key, so the pipeline
    # can drive progress without a frontend rename.
    EXPLOITABILITY_VERIFICATION = "exploitability_verification"
    # E5: AI logic-vulnerability supplement pass. Opt-in (``logic_vuln`` flag).
    # Runs after exploitability so logic findings (which carry their own grounded
    # evidence and have no source→sink taint) skip taint verification and flow
    # straight into deduplication/adjudication.
    LOGIC_VULN_DISCOVERY = "logic_vuln_discovery"
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


# Canonical execution order of all scan phases. Single source of truth for
# resume-skip computation (checkpoint_service.get_resume_strategy) and
# ScanExecutor._create_initial_phases — both of which previously used the
# legacy PhaseName enum and never matched the pipeline's actual phase values
# (Phase 18/P5-A5).
SCAN_PHASE_ORDER: list[ScanPhase] = [
    ScanPhase.L1_PREPARATION,
    ScanPhase.SOURCE_PREPARATION,
    ScanPhase.ENGINE_SELECTION,
    ScanPhase.ENGINE_EXECUTION,
    ScanPhase.EXPLOITABILITY_VERIFICATION,
    ScanPhase.LOGIC_VULN_DISCOVERY,
    ScanPhase.ADJUDICATION,
    ScanPhase.ADVERSARIAL,
    ScanPhase.RESULT_MERGE,
    ScanPhase.TOKEN_STATS,
]


# Read-only compatibility map: legacy CLI-era PhaseName values (CamelCase,
# 7 phases) → canonical ScanPhase values. Lets resume reason about checkpoints
# written before the PhaseName→ScanPhase convergence without a DB migration.
_LEGACY_PHASE_ALIASES: dict[str, str] = {
    "L1_preparation": ScanPhase.L1_PREPARATION.value,
    "L1_attack_surface": ScanPhase.SOURCE_PREPARATION.value,
    "L2_semgrep": ScanPhase.ENGINE_EXECUTION.value,
    "L2_codeql": ScanPhase.ENGINE_EXECUTION.value,
    "L3_agent": ScanPhase.ENGINE_EXECUTION.value,
    "L3_adjudication": ScanPhase.ADJUDICATION.value,
    "report_generation": ScanPhase.RESULT_MERGE.value,
}
