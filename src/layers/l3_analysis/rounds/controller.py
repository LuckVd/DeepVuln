"""
Round Controller

Manages the execution of multi-round audit process.
"""

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Awaitable, Callable

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.rounds.models import (
    AuditSession,
    ConfidenceLevel,
    CoverageStats,
    EngineStats,
    RoundResult,
    RoundStatus,
    VulnerabilityCandidate,
)
from src.layers.l3_analysis.strategy.models import AuditStrategy


class RoundController:
    """
    Controls the multi-round audit process.

    The controller:
    1. Manages round execution order
    2. Tracks progress across rounds
    3. Decides when to stop auditing
    4. Aggregates results from all rounds
    """

    # Default configuration
    DEFAULT_MAX_ROUNDS = 3
    DEFAULT_STOP_ON_CRITICAL = True
    DEFAULT_MIN_CANDIDATES_FOR_NEXT_ROUND = 1

    def __init__(
        self,
        max_rounds: int = DEFAULT_MAX_ROUNDS,
        stop_on_critical: bool = DEFAULT_STOP_ON_CRITICAL,
        min_candidates_for_next_round: int = DEFAULT_MIN_CANDIDATES_FOR_NEXT_ROUND,
        on_round_complete: Callable[[RoundResult], None] | None = None,
        on_session_complete: Callable[[AuditSession], None] | None = None,
    ):
        """
        Initialize the round controller.

        Args:
            max_rounds: Maximum number of rounds to execute.
            stop_on_critical: Stop if a critical vulnerability is confirmed.
            min_candidates_for_next_round: Minimum candidates needed to continue.
            on_round_complete: Callback when a round completes.
            on_session_complete: Callback when the session completes.
        """
        self.logger = get_logger(__name__)
        self.max_rounds = max_rounds
        self.stop_on_critical = stop_on_critical
        self.min_candidates_for_next_round = min_candidates_for_next_round
        self.on_round_complete = on_round_complete
        self.on_session_complete = on_session_complete

        # Session state
        self._session: AuditSession | None = None
        self._strategy: AuditStrategy | None = None

    @property
    def current_round(self) -> int:
        """Current round number."""
        if self._session:
            return self._session.current_round
        return 0

    @property
    def session(self) -> AuditSession | None:
        """Current audit session."""
        return self._session

    def start_session(
        self,
        source_path: Path,
        strategy: AuditStrategy,
        project_name: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> AuditSession:
        """
        Start a new audit session.

        Args:
            source_path: Path to source code.
            strategy: Audit strategy to execute.
            project_name: Project name (defaults to directory name).
            config: Session configuration.

        Returns:
            New audit session.
        """
        if not project_name:
            project_name = source_path.name

        self._session = AuditSession(
            id=f"audit-{uuid.uuid4().hex[:8]}",
            project_name=project_name,
            source_path=str(source_path),
            max_rounds=self.max_rounds,
            config=config or {},
            status=RoundStatus.PENDING,
            started_at=datetime.now(UTC),
        )

        self._strategy = strategy

        self.logger.info(
            f"Started audit session {self._session.id} "
            f"for {project_name} ({strategy.total_targets} targets)"
        )

        return self._session

    async def execute_round(
        self,
        executor: Callable[[AuditStrategy, RoundResult | None], "Awaitable[RoundResult]"],
    ) -> RoundResult:
        """
        Execute a single round.

        Args:
            executor: Async function that executes a round.

        Returns:
            Round result.

        Raises:
            RuntimeError: If no session is active.
        """
        if not self._session or not self._strategy:
            raise RuntimeError("No active audit session. Call start_session() first.")

        round_number = self._session.current_round + 1
        self.logger.info(f"Starting round {round_number}")

        # Get previous round result (if any)
        previous_round = self._session.get_current_round()

        # Execute the round
        self._session.status = RoundStatus.RUNNING
        result = await executor(self._strategy, previous_round)

        # Add to session
        self._session.add_round(result)

        # Callback
        if self.on_round_complete:
            self.on_round_complete(result)

        self.logger.info(
            f"Round {round_number} completed: "
            f"{result.total_candidates} candidates, "
            f"{len(result.next_round_candidates)} for next round"
        )

        # Check termination conditions
        self._check_termination()

        return result

    async def execute_all_rounds(
        self,
        executor_factory: Callable[[int], Callable[[AuditStrategy, RoundResult | None], "Awaitable[RoundResult]"]],
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> AuditSession:
        """
        Execute all rounds until completion or termination.

        Args:
            executor_factory: Factory that creates round executors by round number.
            progress_callback: Callback for progress updates.

        Returns:
            Completed audit session.

        Raises:
            RuntimeError: If no session is active.
        """
        if not self._session or not self._strategy:
            raise RuntimeError("No active audit session. Call start_session() first.")

        self.logger.info(
            f"Starting multi-round audit (max {self.max_rounds} rounds)"
        )

        while self._should_continue():
            round_number = self._session.current_round + 1
            executor = executor_factory(round_number)

            await self.execute_round(executor)

            if progress_callback:
                progress_callback(round_number, self.max_rounds)

        # Mark session complete
        self._session.mark_completed()

        # Callback
        if self.on_session_complete:
            self.on_session_complete(self._session)

        self.logger.info(
            f"Audit session completed: {len(self._session.all_candidates)} candidates, "
            f"{len(self._session.confirmed_vulnerabilities)} confirmed"
        )

        return self._session

    def _should_continue(self) -> bool:
        """Check if audit should continue to next round."""
        if not self._session:
            return False

        # Check max rounds
        if self._session.current_round >= self.max_rounds:
            self.logger.info(f"Max rounds ({self.max_rounds}) reached")
            return False

        # Check if session already completed/failed
        if self._session.status in (RoundStatus.COMPLETED, RoundStatus.FAILED):
            return False

        # Check for critical confirmed vulnerability
        if self.stop_on_critical and self._session.confirmed_vulnerabilities:
            for vuln in self._session.confirmed_vulnerabilities:
                if vuln.finding.severity.value == "critical":
                    self.logger.info("Stopping: critical vulnerability confirmed")
                    return False

        # Check for next round candidates
        current_round = self._session.get_current_round()
        if current_round:
            if len(current_round.next_round_candidates) < self.min_candidates_for_next_round:
                self.logger.info(
                    f"Stopping: insufficient candidates for next round "
                    f"({len(current_round.next_round_candidates)} < {self.min_candidates_for_next_round})"
                )
                return False

        return True

    def _check_termination(self) -> None:
        """Check and handle termination conditions."""
        if not self._session:
            return

        current_round = self._session.get_current_round()
        if not current_round:
            return

        # Check for critical findings
        if self.stop_on_critical:
            critical_candidates = current_round.get_candidates_by_severity(
                [type('SeverityLevel', (), {'value': 'critical'})]
            )
            for candidate in current_round.candidates:
                if (
                    candidate.finding.severity.value == "critical"
                    and candidate.confidence == ConfidenceLevel.HIGH
                ):
                    self._session.confirmed_vulnerabilities.append(candidate)
                    self.logger.warning(
                        f"Critical vulnerability confirmed: {candidate.finding.title}"
                    )

    def confirm_vulnerability(self, candidate_id: str) -> VulnerabilityCandidate | None:
        """
        Confirm a candidate as a real vulnerability.

        Args:
            candidate_id: ID of the candidate to confirm.

        Returns:
            The confirmed candidate, or None if not found.
        """
        if not self._session:
            return None

        for candidate in self._session.all_candidates:
            if candidate.id == candidate_id:
                if candidate not in self._session.confirmed_vulnerabilities:
                    self._session.confirmed_vulnerabilities.append(candidate)
                    self.logger.info(f"Confirmed vulnerability: {candidate.finding.title}")
                return candidate

        return None

    def mark_false_positive(self, candidate_id: str) -> VulnerabilityCandidate | None:
        """
        Mark a candidate as a false positive.

        Args:
            candidate_id: ID of the candidate to mark.

        Returns:
            The marked candidate, or None if not found.
        """
        if not self._session:
            return None

        for candidate in self._session.all_candidates:
            if candidate.id == candidate_id:
                if candidate not in self._session.false_positives:
                    self._session.false_positives.append(candidate)
                    self.logger.info(f"Marked as false positive: {candidate.finding.title}")
                return candidate

        return None

    def get_statistics(self) -> dict[str, Any]:
        """Get current session statistics."""
        if not self._session:
            return {
                "status": "no_session",
                "message": "No active audit session",
            }

        return self._session.get_statistics()

    def reset(self) -> None:
        """Reset the controller state."""
        self._session = None
        self._strategy = None
        self.logger.info("Round controller reset")
