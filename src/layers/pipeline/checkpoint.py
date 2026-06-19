"""Checkpoint sink protocol for resume support.

Implementations live in the web layer (wrapping ``CheckpointService``); the
pipeline depends only on this protocol to respect layering (layers must not
import web).
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class CheckpointSink(Protocol):
    """Persists phase completion so a scan can resume after interruption."""

    # Phases already completed (loaded from a prior checkpoint); the pipeline
    # skips these on resume.
    skip_phases: list[str]

    async def save(self, phase: str, data: dict[str, Any] | None = None) -> None:
        """Persist completion of ``phase``. Must never raise (checkpoint
        failures must not break a scan)."""
        ...

    async def clean(self) -> None:
        """Remove the checkpoint once the scan finishes successfully."""
        ...
