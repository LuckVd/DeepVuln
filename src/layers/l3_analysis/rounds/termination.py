"""
Round Termination Decision Module

Provides intelligent decision-making for when to terminate multi-round audits.
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, computed_field

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.rounds.models import (
    AuditSession,
    ConfidenceLevel,
    RoundResult,
)


class TerminationReason(str, Enum):
    """Reasons for terminating the audit."""

    MAX_ROUNDS_REACHED = "max_rounds_reached"  # Reached maximum round limit
    NO_CANDIDATES = "no_candidates"  # No candidates for next round
    CONFIDENCE_THRESHOLD = "confidence_threshold"  # All candidates have sufficient confidence
    DIMINISHING_RETURNS = "diminishing_returns"  # New findings below threshold
    RESOURCE_EXHAUSTED = "resource_exhausted"  # Time/token/cost limit reached
    MANUAL_STOP = "manual_stop"  # User requested stop
    CRITICAL_FOUND = "critical_found"  # Critical vulnerability confirmed


class FindingsTrend(str, Enum):
    """Trend of findings across rounds."""

    INCREASING = "increasing"  # More findings each round
    STABLE = "stable"  # Similar findings each round
    DECREASING = "decreasing"  # Fewer findings each round
    INSUFFICIENT_DATA = "insufficient_data"  # Not enough rounds to determine


class DecisionMetrics(BaseModel):
    """
    Metrics used for termination decision.

    Collects various indicators to help decide whether to continue auditing.
    """

    # Candidate status
    total_candidates: int = Field(default=0, description="Total candidates across all rounds")
    high_confidence_count: int = Field(default=0, description="High confidence candidates")
    medium_confidence_count: int = Field(default=0, description="Medium confidence candidates")
    low_confidence_count: int = Field(default=0, description="Low confidence candidates")

    # Benefit metrics
    new_findings_last_round: int = Field(default=0, description="New findings in the most recent round")
    avg_findings_per_round: float = Field(default=0.0, description="Average findings per round")
    findings_trend: FindingsTrend = Field(
        default=FindingsTrend.INSUFFICIENT_DATA,
        description="Trend of findings across rounds",
    )

    # Resource metrics
    elapsed_time_seconds: float = Field(default=0.0, description="Total elapsed time")
    tokens_used: int = Field(default=0, description="Total tokens used")
    estimated_cost: float = Field(default=0.0, description="Estimated cost in USD")

    # Round metrics
    rounds_completed: int = Field(default=0, description="Number of rounds completed")
    candidates_for_next_round: int = Field(default=0, description="Candidates pending next round")

    # Scores (0.0 - 1.0)
    continue_benefit_score: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Score for expected benefit of continuing",
    )
    continue_cost_score: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Score for expected cost of continuing",
    )

    @computed_field
    @property
    def net_benefit_score(self) -> float:
        """Net benefit score (benefit - cost)."""
        return self.continue_benefit_score - self.continue_cost_score

    @computed_field
    @property
    def high_confidence_ratio(self) -> float:
        """Ratio of high confidence candidates."""
        if self.total_candidates == 0:
            return 0.0
        return self.high_confidence_count / self.total_candidates

    @computed_field
    @property
    def findings_per_minute(self) -> float:
        """Findings rate per minute."""
        if self.elapsed_time_seconds == 0:
            return 0.0
        return (self.total_candidates / self.elapsed_time_seconds) * 60


class TerminationDecision(BaseModel):
    """
    Decision about whether to continue auditing.

    Contains the decision, reason, and supporting metrics.
    """

    should_continue: bool = Field(..., description="Whether audit should continue")
    reason: TerminationReason | None = Field(
        default=None,
        description="Reason for termination (if should_continue=False)",
    )
    metrics: DecisionMetrics = Field(
        default_factory=DecisionMetrics,
        description="Metrics used for the decision",
    )
    explanation: str = Field(
        default="",
        description="Human-readable explanation of the decision",
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence in this decision",
    )

    # Recommendations
    recommended_action: str | None = Field(
        default=None,
        description="Recommended next action",
    )
    estimated_next_round_benefit: float | None = Field(
        default=None,
        description="Estimated benefit of next round",
    )

    # Timestamp
    decided_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When this decision was made",
    )

    def to_summary(self) -> str:
        """Generate a one-line summary."""
        if self.should_continue:
            return f"Continue (benefit: {self.metrics.continue_benefit_score:.2f})"
        return f"Stop: {self.reason.value if self.reason else 'unknown'}"


class TerminationConfig(BaseModel):
    """Configuration for termination decision."""

    # Confidence thresholds
    high_confidence_threshold: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Ratio of high confidence candidates to consider stopping",
    )
    min_high_confidence_count: int = Field(
        default=3,
        ge=0,
        description="Minimum high confidence candidates before stopping",
    )

    # Diminishing returns thresholds
    min_new_findings_ratio: float = Field(
        default=0.1,
        ge=0.0,
        le=1.0,
        description="Minimum ratio of new findings to total to continue",
    )
    min_absolute_new_findings: int = Field(
        default=1,
        ge=0,
        description="Minimum absolute new findings to continue",
    )

    # Resource limits
    max_time_seconds: float = Field(
        default=3600.0,  # 1 hour
        ge=0.0,
        description="Maximum time in seconds",
    )
    max_tokens: int = Field(
        default=1_000_000,
        ge=0,
        description="Maximum tokens to use",
    )
    max_cost_usd: float = Field(
        default=50.0,
        ge=0.0,
        description="Maximum cost in USD",
    )

    # Benefit/cost scoring weights
    benefit_weight_new_findings: float = Field(
        default=0.4,
        ge=0.0,
        le=1.0,
        description="Weight for new findings in benefit score",
    )
    benefit_weight_pending_candidates: float = Field(
        default=0.3,
        ge=0.0,
        le=1.0,
        description="Weight for pending candidates in benefit score",
    )
    benefit_weight_low_confidence: float = Field(
        default=0.3,
        ge=0.0,
        le=1.0,
        description="Weight for low confidence candidates in benefit score",
    )

    cost_weight_time: float = Field(
        default=0.3,
        ge=0.0,
        le=1.0,
        description="Weight for time in cost score",
    )
    cost_weight_tokens: float = Field(
        default=0.4,
        ge=0.0,
        le=1.0,
        description="Weight for tokens in cost score",
    )
    cost_weight_money: float = Field(
        default=0.3,
        ge=0.0,
        le=1.0,
        description="Weight for money in cost score",
    )

    # Trend detection
    trend_window_size: int = Field(
        default=3,
        ge=2,
        description="Number of rounds to consider for trend detection",
    )


class TerminationDecider:
    """
    Intelligent termination decision maker.

    Analyzes session state and metrics to decide whether to continue auditing.
    """

    def __init__(self, config: TerminationConfig | None = None):
        """
        Initialize the termination decider.

        Args:
            config: Configuration for termination decisions.
        """
        self.logger = get_logger(__name__)
        self.config = config or TerminationConfig()

    def should_continue(
        self,
        session: AuditSession,
        current_round: RoundResult | None = None,
    ) -> TerminationDecision:
        """
        Decide whether the audit should continue to another round.

        Args:
            session: Current audit session.
            current_round: Current round result (optional, uses latest if not provided).

        Returns:
            TerminationDecision with the decision and reasoning.
        """
        if current_round is None:
            current_round = session.get_current_round()

        # Collect metrics
        metrics = self._collect_metrics(session, current_round)

        # Check termination conditions in order of priority

        # 1. Check max rounds
        if session.current_round >= session.max_rounds:
            return self._make_decision(
                should_continue=False,
                reason=TerminationReason.MAX_ROUNDS_REACHED,
                metrics=metrics,
                explanation=f"Maximum rounds ({session.max_rounds}) reached",
            )

        # 2. Check for no candidates
        if current_round and not current_round.next_round_candidates:
            return self._make_decision(
                should_continue=False,
                reason=TerminationReason.NO_CANDIDATES,
                metrics=metrics,
                explanation="No candidates pending for next round",
            )

        # 3. Check confidence threshold
        if self._is_confidence_threshold_met(session, metrics):
            return self._make_decision(
                should_continue=False,
                reason=TerminationReason.CONFIDENCE_THRESHOLD,
                metrics=metrics,
                explanation=f"High confidence ratio ({metrics.high_confidence_ratio:.1%}) "
                f"exceeds threshold ({self.config.high_confidence_threshold:.1%})",
            )

        # 4. Check diminishing returns
        if self._is_diminishing_returns(session, metrics):
            return self._make_decision(
                should_continue=False,
                reason=TerminationReason.DIMINISHING_RETURNS,
                metrics=metrics,
                explanation=f"Diminishing returns detected: only {metrics.new_findings_last_round} "
                f"new findings in last round (trend: {metrics.findings_trend.value})",
            )

        # 5. Check resource exhaustion
        resource_reason = self._check_resource_exhaustion(metrics)
        if resource_reason:
            return self._make_decision(
                should_continue=False,
                reason=resource_reason,
                metrics=metrics,
                explanation=f"Resource limit reached",
            )

        # 6. Check benefit vs cost
        if metrics.net_benefit_score < 0:
            return self._make_decision(
                should_continue=False,
                reason=TerminationReason.DIMINISHING_RETURNS,
                metrics=metrics,
                explanation=f"Expected cost ({metrics.continue_cost_score:.2f}) "
                f"exceeds expected benefit ({metrics.continue_benefit_score:.2f})",
            )

        # All checks passed, continue
        return self._make_decision(
            should_continue=True,
            reason=None,
            metrics=metrics,
            explanation=f"Continuing audit: benefit score {metrics.continue_benefit_score:.2f}, "
            f"{metrics.candidates_for_next_round} candidates pending",
            recommended_action=self._get_recommended_action(session, metrics),
            estimated_next_round_benefit=metrics.continue_benefit_score,
        )

    def _collect_metrics(
        self,
        session: AuditSession,
        current_round: RoundResult | None,
    ) -> DecisionMetrics:
        """Collect metrics from the session."""
        metrics = DecisionMetrics()

        # Candidate counts
        metrics.total_candidates = len(session.all_candidates)
        for candidate in session.all_candidates:
            if candidate.confidence == ConfidenceLevel.HIGH:
                metrics.high_confidence_count += 1
            elif candidate.confidence == ConfidenceLevel.MEDIUM:
                metrics.medium_confidence_count += 1
            else:
                metrics.low_confidence_count += 1

        # Findings metrics
        metrics.rounds_completed = len(session.rounds)
        if current_round:
            metrics.new_findings_last_round = current_round.total_candidates
            metrics.candidates_for_next_round = len(current_round.next_round_candidates)

        if session.rounds:
            findings_counts = [r.total_candidates for r in session.rounds]
            metrics.avg_findings_per_round = sum(findings_counts) / len(findings_counts)
            metrics.findings_trend = self._detect_trend(findings_counts)

        # Resource metrics
        if session.started_at:
            metrics.elapsed_time_seconds = (
                datetime.now(UTC) - session.started_at
            ).total_seconds()

        # Calculate tokens and cost from engine stats
        for round_result in session.rounds:
            for engine_stats in round_result.engine_stats.values():
                metrics.tokens_used += engine_stats.tokens_used
                # Estimate cost (rough approximation)
                metrics.estimated_cost += engine_stats.tokens_used * 0.00001  # $0.01 per 1K tokens

        # Calculate benefit and cost scores
        metrics.continue_benefit_score = self._calculate_benefit_score(metrics)
        metrics.continue_cost_score = self._calculate_cost_score(metrics)

        return metrics

    def _detect_trend(self, findings_counts: list[int]) -> FindingsTrend:
        """Detect the trend of findings across rounds."""
        if len(findings_counts) < 2:
            return FindingsTrend.INSUFFICIENT_DATA

        # Use only the last N rounds for trend detection
        window = findings_counts[-self.config.trend_window_size:]
        if len(window) < 2:
            return FindingsTrend.INSUFFICIENT_DATA

        # Calculate trend direction
        increases = 0
        decreases = 0
        for i in range(1, len(window)):
            if window[i] > window[i - 1]:
                increases += 1
            elif window[i] < window[i - 1]:
                decreases += 1

        if increases > decreases:
            return FindingsTrend.INCREASING
        elif decreases > increases:
            return FindingsTrend.DECREASING
        return FindingsTrend.STABLE

    def _is_confidence_threshold_met(
        self,
        session: AuditSession,
        metrics: DecisionMetrics,
    ) -> bool:
        """Check if confidence threshold is met."""
        # Need minimum candidates before checking threshold
        if metrics.total_candidates < self.config.min_high_confidence_count:
            return False

        # Check high confidence ratio
        return metrics.high_confidence_ratio >= self.config.high_confidence_threshold

    def _is_diminishing_returns(
        self,
        session: AuditSession,
        metrics: DecisionMetrics,
    ) -> bool:
        """Check if we're seeing diminishing returns."""
        # Need at least 2 rounds to detect diminishing returns
        if metrics.rounds_completed < 2:
            return False

        # Check absolute new findings
        if metrics.new_findings_last_round < self.config.min_absolute_new_findings:
            return True

        # Check ratio of new findings to total
        if metrics.total_candidates > 0:
            new_ratio = metrics.new_findings_last_round / metrics.total_candidates
            if new_ratio < self.config.min_new_findings_ratio:
                return True

        # Check trend direction
        if metrics.findings_trend == FindingsTrend.DECREASING:
            # Additional check: is the decrease significant?
            if len(session.rounds) >= 2:
                last_count = session.rounds[-1].total_candidates
                prev_count = session.rounds[-2].total_candidates
                if prev_count > 0:
                    decrease_ratio = (prev_count - last_count) / prev_count
                    if decrease_ratio > 0.5:  # More than 50% decrease
                        return True

        return False

    def _check_resource_exhaustion(
        self,
        metrics: DecisionMetrics,
    ) -> TerminationReason | None:
        """Check if any resource limit has been reached."""
        # Check time limit
        if metrics.elapsed_time_seconds >= self.config.max_time_seconds:
            return TerminationReason.RESOURCE_EXHAUSTED

        # Check token limit
        if metrics.tokens_used >= self.config.max_tokens:
            return TerminationReason.RESOURCE_EXHAUSTED

        # Check cost limit
        if metrics.estimated_cost >= self.config.max_cost_usd:
            return TerminationReason.RESOURCE_EXHAUSTED

        return None

    def _calculate_benefit_score(self, metrics: DecisionMetrics) -> float:
        """Calculate the expected benefit of continuing."""
        score = 0.0

        # Benefit from potential new findings (based on trend)
        if metrics.findings_trend == FindingsTrend.INCREASING:
            trend_factor = 1.2
        elif metrics.findings_trend == FindingsTrend.STABLE:
            trend_factor = 1.0
        elif metrics.findings_trend == FindingsTrend.DECREASING:
            trend_factor = 0.7
        else:
            trend_factor = 1.0

        # New findings potential
        new_findings_score = min(
            1.0,
            (metrics.new_findings_last_round / max(1, metrics.avg_findings_per_round)) * trend_factor
        )
        score += new_findings_score * self.config.benefit_weight_new_findings

        # Pending candidates benefit
        pending_score = min(1.0, metrics.candidates_for_next_round / 10)
        score += pending_score * self.config.benefit_weight_pending_candidates

        # Low confidence candidates benefit (more to discover)
        if metrics.total_candidates > 0:
            low_ratio = metrics.low_confidence_count / metrics.total_candidates
            low_confidence_score = low_ratio  # Higher is better here
            score += low_confidence_score * self.config.benefit_weight_low_confidence

        return min(1.0, score)

    def _calculate_cost_score(self, metrics: DecisionMetrics) -> float:
        """Calculate the expected cost of continuing."""
        score = 0.0

        # Time cost
        time_ratio = metrics.elapsed_time_seconds / self.config.max_time_seconds
        score += time_ratio * self.config.cost_weight_time

        # Token cost
        token_ratio = metrics.tokens_used / self.config.max_tokens
        score += token_ratio * self.config.cost_weight_tokens

        # Money cost
        cost_ratio = metrics.estimated_cost / self.config.max_cost_usd
        score += cost_ratio * self.config.cost_weight_money

        return min(1.0, score)

    def _get_recommended_action(
        self,
        session: AuditSession,
        metrics: DecisionMetrics,
    ) -> str:
        """Get recommended action for the next round."""
        if metrics.candidates_for_next_round > 0:
            return f"Continue with {metrics.candidates_for_next_round} pending candidates"
        elif metrics.low_confidence_count > metrics.high_confidence_count:
            return "Focus on deep analysis of low-confidence candidates"
        else:
            return "Proceed with standard analysis"

    def _make_decision(
        self,
        should_continue: bool,
        reason: TerminationReason | None,
        metrics: DecisionMetrics,
        explanation: str,
        recommended_action: str | None = None,
        estimated_next_round_benefit: float | None = None,
    ) -> TerminationDecision:
        """Create a termination decision."""
        decision = TerminationDecision(
            should_continue=should_continue,
            reason=reason,
            metrics=metrics,
            explanation=explanation,
            confidence=0.9 if metrics.rounds_completed >= 2 else 0.7,
            recommended_action=recommended_action,
            estimated_next_round_benefit=estimated_next_round_benefit,
        )

        self.logger.info(f"Termination decision: {decision.to_summary()}")
        return decision


# Default configuration instance
DEFAULT_TERMINATION_CONFIG = TerminationConfig()
