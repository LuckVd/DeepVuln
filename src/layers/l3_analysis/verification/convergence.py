"""
Convergence Checker for Enhanced Adversarial Verification.

Determines when multi-round adversarial debates should converge (stop).
Supports multiple convergence criteria and strategy stability detection.
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from .models import AdversarialVerdict, VerdictType
from .strategy_library import AttackStrategy, DefenseStrategy


class ConvergenceReason(str, Enum):
    """Reasons for convergence."""

    HIGH_CONFIDENCE = "high_confidence"  # Verdict confidence above threshold
    DECISIVE_VERDICT = "decisive_verdict"  # Clear winner (CONFIRMED/FALSE_POSITIVE)
    MAX_ROUNDS_REACHED = "max_rounds_reached"  # Hit maximum rounds limit
    STRATEGY_STABLE = "strategy_stable"  # No new strategies being generated
    STRENGTH_GAP = "strength_gap"  # Large gap between attacker/defender strength
    NO_PROGRESS = "no_progress"  # No improvement in recent rounds
    COST_LIMIT = "cost_limit"  # Token/cost limit reached


class ConvergenceConfig(BaseModel):
    """Configuration for convergence checking."""

    # Basic limits
    max_rounds: int = Field(default=5, ge=1, le=10, description="Maximum debate rounds")
    min_rounds: int = Field(default=1, ge=1, description="Minimum rounds before checking convergence")

    # Confidence thresholds
    confidence_threshold: float = Field(
        default=0.85,
        ge=0.5,
        le=1.0,
        description="Confidence threshold for early convergence",
    )
    strength_diff_threshold: float = Field(
        default=0.35,
        ge=0.1,
        le=0.5,
        description="Strength difference threshold for decisive verdict",
    )

    # Progress tracking
    progress_window: int = Field(
        default=2,
        ge=1,
        le=5,
        description="Number of rounds to check for progress",
    )
    min_progress_threshold: float = Field(
        default=0.05,
        ge=0.01,
        le=0.2,
        description="Minimum confidence improvement to consider progress",
    )

    # Strategy stability
    strategy_stability_rounds: int = Field(
        default=2,
        ge=1,
        le=4,
        description="Rounds with no new strategies to consider stable",
    )

    # Cost limits
    max_tokens_per_finding: int = Field(
        default=50000,
        ge=10000,
        description="Maximum tokens per finding verification",
    )


class RoundSummary(BaseModel):
    """Summary of a single debate round."""

    round_number: int = Field(..., description="Round number")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Verdict info
    verdict_type: VerdictType = Field(..., description="Verdict type")
    verdict_confidence: float = Field(..., ge=0.0, le=1.0, description="Verdict confidence")
    attacker_strength: float = Field(..., ge=0.0, le=1.0, description="Attacker strength")
    defender_strength: float = Field(..., ge=0.0, le=1.0, description="Defender strength")

    # Strategy info
    attacker_strategy_id: str | None = Field(default=None)
    defender_strategy_id: str | None = Field(default=None)
    new_attacker_strategies: int = Field(default=0, description="New attacker strategies generated")
    new_defender_strategies: int = Field(default=0, description="New defender strategies generated")

    # Cost tracking
    tokens_used: int = Field(default=0)

    @property
    def strength_diff(self) -> float:
        """Get absolute strength difference."""
        return abs(self.attacker_strength - self.defender_strength)

    @property
    def is_decisive(self) -> bool:
        """Check if this round had a decisive verdict."""
        if self.verdict_type in [VerdictType.CONFIRMED, VerdictType.FALSE_POSITIVE]:
            if self.verdict_confidence >= 0.7 and self.strength_diff >= 0.3:
                return True
        return False


class ConvergenceState(BaseModel):
    """Current state of convergence checking."""

    config: ConvergenceConfig = Field(default_factory=ConvergenceConfig)
    round_summaries: list[RoundSummary] = Field(default_factory=list)
    total_tokens_used: int = Field(default=0)

    # Strategy tracking
    attacker_strategy_ids: set[str] = Field(default_factory=set)
    defender_strategy_ids: set[str] = Field(default_factory=set)
    rounds_without_new_attacker_strategy: int = Field(default=0)
    rounds_without_new_defender_strategy: int = Field(default=0)

    # Progress tracking
    confidence_history: list[float] = Field(default_factory=list)

    def current_round(self) -> int:
        """Get current round number."""
        return len(self.round_summaries)

    def last_round(self) -> RoundSummary | None:
        """Get last round summary."""
        return self.round_summaries[-1] if self.round_summaries else None


class ConvergenceResult(BaseModel):
    """Result of convergence check."""

    should_converge: bool = Field(..., description="Whether to stop debating")
    reason: ConvergenceReason = Field(..., description="Why converging (or not)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Final confidence")
    message: str = Field(..., description="Human-readable message")

    # Additional info
    rounds_completed: int = Field(default=0)
    final_verdict_type: VerdictType | None = Field(default=None)
    progress_made: bool = Field(default=True, description="Whether progress was made overall")


class ConvergenceChecker:
    """
    Checks convergence conditions for multi-round adversarial debates.

    Supports multiple convergence criteria:
    1. Confidence threshold reached
    2. Decisive verdict (CONFIRMED/FALSE_POSITIVE with large strength gap)
    3. Maximum rounds reached
    4. No new strategies being generated
    5. No progress in recent rounds
    6. Cost limit reached
    """

    def __init__(self, config: ConvergenceConfig | None = None):
        """Initialize convergence checker."""
        self.config = config or ConvergenceConfig()
        self.state = ConvergenceState(config=self.config)

    def record_round(
        self,
        verdict: AdversarialVerdict,
        attacker_strategy: AttackStrategy | None = None,
        defender_strategy: DefenseStrategy | None = None,
        new_attacker_strategies: int = 0,
        new_defender_strategies: int = 0,
        tokens_used: int = 0,
    ) -> ConvergenceResult:
        """
        Record a debate round and check for convergence.

        Args:
            verdict: The verdict from this round.
            attacker_strategy: The attacker strategy used.
            defender_strategy: The defender strategy used.
            new_attacker_strategies: Number of new attacker strategies generated.
            new_defender_strategies: Number of new defender strategies generated.
            tokens_used: Tokens used in this round.

        Returns:
            ConvergenceResult indicating whether to stop.
        """
        round_number = self.state.current_round() + 1

        # Create round summary
        summary = RoundSummary(
            round_number=round_number,
            verdict_type=verdict.verdict,
            verdict_confidence=verdict.confidence,
            attacker_strength=verdict.attacker_strength,
            defender_strength=verdict.defender_strength,
            attacker_strategy_id=attacker_strategy.strategy_id if attacker_strategy else None,
            defender_strategy_id=defender_strategy.strategy_id if defender_strategy else None,
            new_attacker_strategies=new_attacker_strategies,
            new_defender_strategies=new_defender_strategies,
            tokens_used=tokens_used,
        )

        # Update state
        self.state.round_summaries.append(summary)
        self.state.total_tokens_used += tokens_used
        self.state.confidence_history.append(verdict.confidence)

        # Track strategy stability
        if attacker_strategy:
            if attacker_strategy.strategy_id in self.state.attacker_strategy_ids:
                self.state.rounds_without_new_attacker_strategy += 1
            else:
                self.state.attacker_strategy_ids.add(attacker_strategy.strategy_id)
                self.state.rounds_without_new_attacker_strategy = 0

        if defender_strategy:
            if defender_strategy.strategy_id in self.state.defender_strategy_ids:
                self.state.rounds_without_new_defender_strategy += 1
            else:
                self.state.defender_strategy_ids.add(defender_strategy.strategy_id)
                self.state.rounds_without_new_defender_strategy = 0

        # Check convergence
        return self._check_convergence(verdict)

    def _check_convergence(self, verdict: AdversarialVerdict) -> ConvergenceResult:
        """Check all convergence conditions."""
        current_round = self.state.current_round()

        # Check minimum rounds
        if current_round < self.config.min_rounds:
            return self._continue_result(
                f"Minimum rounds ({self.config.min_rounds}) not yet reached"
            )

        # Check max rounds
        if current_round >= self.config.max_rounds:
            return self._converge_result(
                ConvergenceReason.MAX_ROUNDS_REACHED,
                verdict,
                f"Maximum rounds ({self.config.max_rounds}) reached",
            )

        # Check high confidence
        if verdict.confidence >= self.config.confidence_threshold:
            return self._converge_result(
                ConvergenceReason.HIGH_CONFIDENCE,
                verdict,
                f"High confidence reached ({verdict.confidence:.0%} >= {self.config.confidence_threshold:.0%})",
            )

        # Check decisive verdict
        if self._is_decisive_verdict(verdict):
            return self._converge_result(
                ConvergenceReason.DECISIVE_VERDICT,
                verdict,
                f"Decisive verdict: {verdict.verdict.value} with strength diff {verdict.attacker_strength - verdict.defender_strength:.2f}",
            )

        # Check strength gap
        strength_diff = abs(verdict.attacker_strength - verdict.defender_strength)
        if strength_diff >= self.config.strength_diff_threshold:
            return self._converge_result(
                ConvergenceReason.STRENGTH_GAP,
                verdict,
                f"Large strength gap ({strength_diff:.2f} >= {self.config.strength_diff_threshold:.2f})",
            )

        # Check strategy stability
        if self._is_strategy_stable():
            return self._converge_result(
                ConvergenceReason.STRATEGY_STABLE,
                verdict,
                f"No new strategies for {self.config.strategy_stability_rounds} rounds",
            )

        # Check no progress
        if self._has_no_progress():
            return self._converge_result(
                ConvergenceReason.NO_PROGRESS,
                verdict,
                f"No confidence improvement in last {self.config.progress_window} rounds",
                progress_made=False,
            )

        # Check cost limit
        if self.state.total_tokens_used >= self.config.max_tokens_per_finding:
            return self._converge_result(
                ConvergenceReason.COST_LIMIT,
                verdict,
                f"Token limit reached ({self.state.total_tokens_used} >= {self.config.max_tokens_per_finding})",
            )

        # Continue debating
        return self._continue_result("No convergence criteria met")

    def _is_decisive_verdict(self, verdict: AdversarialVerdict) -> bool:
        """Check if verdict is decisive."""
        if verdict.verdict not in [VerdictType.CONFIRMED, VerdictType.FALSE_POSITIVE]:
            return False

        if verdict.confidence < 0.7:
            return False

        strength_diff = abs(verdict.attacker_strength - verdict.defender_strength)
        if strength_diff < 0.3:
            return False

        return True

    def _is_strategy_stable(self) -> bool:
        """Check if strategies have stabilized."""
        min_rounds_for_stability = self.config.strategy_stability_rounds

        if self.state.current_round() < min_rounds_for_stability:
            return False

        # Both attacker and defender must have no new strategies
        return (
            self.state.rounds_without_new_attacker_strategy >= self.config.strategy_stability_rounds
            and self.state.rounds_without_new_defender_strategy >= self.config.strategy_stability_rounds
        )

    def _has_no_progress(self) -> bool:
        """Check if there has been no progress in recent rounds."""
        if len(self.state.confidence_history) < self.config.progress_window + 1:
            return False

        # Check if confidence has not improved in the last N rounds
        recent = self.state.confidence_history[-self.config.progress_window:]
        older = self.state.confidence_history[-(self.config.progress_window + 1)]

        # No progress if max recent confidence is not better than older
        max_recent = max(recent)
        if max_recent <= older + self.config.min_progress_threshold:
            return True

        return False

    def _converge_result(
        self,
        reason: ConvergenceReason,
        verdict: AdversarialVerdict,
        message: str,
        progress_made: bool = True,
    ) -> ConvergenceResult:
        """Create a convergence result."""
        return ConvergenceResult(
            should_converge=True,
            reason=reason,
            confidence=verdict.confidence,
            message=message,
            rounds_completed=self.state.current_round(),
            final_verdict_type=verdict.verdict,
            progress_made=progress_made,
        )

    def _continue_result(self, message: str) -> ConvergenceResult:
        """Create a continue result."""
        last_round = self.state.last_round()
        confidence = last_round.verdict_confidence if last_round else 0.5

        return ConvergenceResult(
            should_converge=False,
            reason=ConvergenceReason.HIGH_CONFIDENCE,  # Placeholder, not used when should_converge=False
            confidence=confidence,
            message=message,
            rounds_completed=self.state.current_round(),
            progress_made=True,
        )

    def reset(self) -> None:
        """Reset the convergence checker for a new debate."""
        self.state = ConvergenceState(config=self.config)

    def get_progress_summary(self) -> dict[str, Any]:
        """Get a summary of debate progress."""
        if not self.state.round_summaries:
            return {
                "rounds_completed": 0,
                "total_tokens": 0,
                "unique_attacker_strategies": 0,
                "unique_defender_strategies": 0,
            }

        summaries = self.state.round_summaries
        first = summaries[0]
        last = summaries[-1]

        return {
            "rounds_completed": len(summaries),
            "total_tokens": self.state.total_tokens_used,
            "unique_attacker_strategies": len(self.state.attacker_strategy_ids),
            "unique_defender_strategies": len(self.state.defender_strategy_ids),
            "confidence_progression": self.state.confidence_history,
            "initial_confidence": first.verdict_confidence,
            "final_confidence": last.verdict_confidence,
            "confidence_improvement": last.verdict_confidence - first.verdict_confidence,
            "initial_verdict": first.verdict_type.value,
            "final_verdict": last.verdict_type.value,
            "verdict_changed": first.verdict_type != last.verdict_type,
        }
