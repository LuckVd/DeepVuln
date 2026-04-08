"""Scan phases.

This module provides phase classes for the different stages of a scan.
Each phase is independent and can be executed concurrently with others.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any
import asyncio
import logging


logger = logging.getLogger(__name__)


@dataclass
class PhaseResult:
    """Result of a phase execution.

    Attributes:
        success: Whether the phase succeeded
        findings: List of findings discovered
        duration_seconds: Phase duration
        tokens_used: Tokens consumed
        error: Error message if failed
    """
    success: bool
    findings: list[dict[str, Any]] | None = None
    duration_seconds: float = 0
    tokens_used: int = 0
    error: str | None = None


class ScanPhase(ABC):
    """Base class for scan phases.

    Each phase represents a distinct stage in the scanning process.
    Phases are executed by the orchestrator and can emit events
    through the provided context.
    """

    def __init__(
        self,
        name: str,
        description: str = "",
    ):
        """Initialize scan phase.

        Args:
            name: Phase name (e.g., "L1_preparation")
            description: Human-readable description
        """
        self.name = name
        self.description = description
        self._start_time: datetime | None = None

    @abstractmethod
    async def execute(
        self,
        context: "ScanContext",  # noqa: F821
    ) -> PhaseResult:
        """Execute the phase.

        Args:
            context: Scan context with state and configuration

        Returns:
            Phase execution result
        """
        ...

    async def _on_start(self, context: "ScanContext") -> None:  # noqa: F821
        """Called when phase starts.

        Args:
            context: Scan context
        """
        self._start_time = datetime.utcnow()
        await context.set_progress(0, self.name)
        logger.info(f"Phase {self.name} started")

    async def _on_complete(
        self,
        context: "ScanContext",  # noqa: F821
        result: PhaseResult,
    ) -> None:
        """Called when phase completes.

        Args:
            context: Scan context
            result: Phase result
        """
        if self._start_time:
            result.duration_seconds = (datetime.utcnow() - self._start_time).total_seconds()
        logger.info(f"Phase {self.name} completed in {result.duration_seconds:.2f}s")

    async def run(
        self,
        context: "ScanContext",  # noqa: F821
    ) -> PhaseResult:
        """Run the phase with lifecycle hooks.

        Args:
            context: Scan context

        Returns:
            Phase execution result
        """
        await self._on_start(context)

        try:
            if context.is_cancelled():
                return PhaseResult(success=False, error="Cancelled")

            result = await self.execute(context)
            await self._on_complete(context, result)
            return result

        except Exception as e:
            logger.error(f"Phase {self.name} failed: {e}", exc_info=True)
            return PhaseResult(success=False, error=str(e))
